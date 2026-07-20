# KOB ステーブルコイン — 4軸適合監査と GAP 充填設計(2026-07-20)

対象 HEAD: `71d8cdcd`。対象コード:
`kob/core/src/contract/stablecoin/`(+ `mint_authority/`)、
`kob/core/src/contract/kcc20/`、`kob/x402/src/`、`kob/engine/`・`kob/domain/`・`kob/settle/`。

本レポートは 6 体の Sonnet 監査エージェントを並列展開して得た所見を、
発行者(main)側で file:line 裏取り・相互検証のうえ統合したものである。監査の軸は
利用者の依頼どおり **(1) ステーブルコインとしての機能完全性 / (2) x402 適合 /
(3) KCC-0020・KCC-0001 適合 / (4) KOB(DEX)適合** の 4 つ。これに **フロー統合性**
と **敵対的健全性再監査** を横断軸として加えた。最後に「**GAP をどう埋めるか**」を
実装優先度つきで設計する。

> **エージェント状態(2026-07-20 時点)**: 6 軸すべて完了(機能完全性は 2 体で相互検証、
> 計 6 体 + 発行者側 file:line 突合)。敵対的再監査で **新 HIGH を 1 件発見**(§6.2、
> 構造前提は発行者側で検証済)。

---

## 0. 総合判定(結論先出し)

**covenant 単体としては完成度が高い。3 つのサブシステム(mint=stablecoin covenant /
pay=x402 / deliver=KCC20・DEX)は個別には testnet-10 で live 実装済みだが、
互いに一切結線されておらず「3 つの島」である。** そして covenant を「規制ステーブル
コイン」「決済トークン」「DEX 上場資産」として見ると、それぞれ別種の GAP が残る。

| 軸 | 判定 | 一言 |
|---|---|---|
| 1. 機能完全性(規制ステーブルコイン) | **概ね実装済み・CRITICAL 1 + 重要 GAP 複数** | issuer の freeze/seize/mint/burn/cap 権限は完備。ただし **鍵漏洩からの復旧経路が無い(CRITICAL)**・**1:1 封緘単位で任意額送金不可**・**address blacklist 不在**・**ROTATE 未実装**・**RAISE_CAP 無上限/無 timelock**・**MINT 無レート制限**・**reserve attestation 不在** |
| 2. x402 適合(alpha.9) | **exact は完全適合・additive は相互運用ギャップ** | `exact/standard-native` は vector 一致・mutation test が load-bearing(105/105 pass)。**KIP-10 `additive` は wire 適合だが実行非互換**(upstream 参照実装と別 shape)。**stablecoin は x402 で運べない**(単なる未結線、KOB 内で解ける。ISSUE-6 は外部トークン用) |
| 3. KCC-0020 / KCC-0001 適合 | **適合(仕様側 open が主)** | State 符号化・P2SH=BLAKE2b・dispatch=BLAKE3 は verbatim 一致。stablecoin は KCC-0020 の **外**の bespoke covenant で正しい。残 GAP は ISSUE-1/11・ISSUE-6・identifier reshape で **すべて upstream-blocked** |
| 4. KOB(DEX)適合 | **未結線・構造的ブロックあり** | `engine/domain/settle` に stablecoin 参照ゼロ。covenant に **「注文になる」遷移が無い**。mass 予算も超過リスク |
| 横: フロー統合性 | **3 つの島** | mint→pay→deliver を貫く経路はコード・テスト・live のどこにも存在しない |
| 横: 敵対的健全性 | **§E CRITICAL は修正済・だが新 HIGH を発見** | successor header の **push-opcode バイト未認証** → 単一 FREEZE 鍵で任意コインを恒久 spend 不能に破壊できる(構造前提は確認済、exploit は未 live 実行) |

**最重要の一文**: KOB のステーブルコインは **Liquid AMP 型の必須 co-signer(準中央集権)
モデル**であり、TRANSFER は毎回 issuer の OPS 署名を要求する(`body.rs:441-444`)。
これは規制ステーブルコインとしては自然だが、**「permissionless な DEX が issuer 署名
なしに約定を settle する」という KOB 本体の前提と正面から衝突する**。GAP 充填設計
(§8)の中核はこの緊張の解消にある。

---

## 1. 機能完全性 — 規制ステーブルコインとして

**エージェント判定**: op 9 種(DEPLOY/MINT/TRANSFER/FREEZE/UNFREEZE/SEIZE/BURN/
RAISE_CAP/MIGRATE)すべて testnet-10 で実機確認済み(`STABLECOIN_E2E_LIVE.md` の
4 回 live。現 HEAD 対応は run4)。issuer 権限構造は CONFIRMED。

### 1.1 機能マトリクス(抜粋、file:line 裏取り済)

| 機能 | 状態 | 証拠 |
|---|---|---|
| MINT / BURN | 実装 | `mint_authority/body.rs:565-821`(anti-backdoor 再構成 + recipient-binding)/ `body.rs:229` BURN sink |
| TRANSFER | 実装(**issuer OPS 共署名必須**) | owner `OpCheckSigVerify`(`body.rs:283-285`)+ OPS `OpCheckSigFromStack`(`body.rs:441-444`)。this coin の `frozen_flag==0` を fail-close(`body.rs:311-313`)、successor の `frozen_flag==CLEAR` を pin(`body.rs:373-393`) |
| FREEZE / UNFREEZE | 実装(単一 op、双方向) | `build_freeze_branch body.rs:524-721`。`new_frozen_flag∈{0x00,0x01}` を bytewise domain gate。UNFREEZE は同分岐を flag=0 で呼ぶだけ(独立 op 無し) |
| SEIZE | 実装(**cold 2-of-3**、owner 署名不要) | `build_seize_branch body.rs:818-1000`、`emit_2of3_threshold body.rs:1019-1065` |
| MIGRATE(upgrade) | 実装(owner + cold 2-of-3 quorum) | `build_migrate_branch body.rs:1378-1473`。live 2 回(run2/run4) |
| supply cap 管理 | 実装 | `mint_authority/body.rs:271-519` RAISE_CAP(cold 2-of-3 `cap_authority`、strict increase) |
| ROTATE(鍵交換) | **未実装(stub)** | `dispatch.rs:104` `UNIMPLEMENTED_BRANCH_STUB`(`OP_0`)→ `body.rs:1519` に配線。実行すれば必ず fail-close。post-Live 延期の明示決定 |
| address blacklist | **不在**(per-coin freeze のみ) | `frozen_flag` は state header 内の **1 コインごと** 1 バイト。アドレス一括凍結の登録簿/SMT root は未実装 |
| global pause | **不在**(形式 flag なし) | `STABLECOIN_ROBUST_DESIGN.md §11-iv`「No formal on-chain global-pause flag」。代替は OPS 署名差し止め=TRANSFER のみ停止 |
| reserve attestation / redemption | **不在** | design doc §8「off-chain, out of scope」 |
| metadata / decimals | **不在**(covenant 内) | `StablecoinStateHeader`(`state.rs:81-88`)に name/symbol/decimals 無し |
| split / merge / batch | **不在**(1:1 固定) | `mod.rs:52-61`「ISSUE-15: 1:1 operating assumption」 |

### 1.2 UTXO モデル固有の重要事実

- **(a) 誰が署名必須か**: TRANSFER = owner + **issuer OPS を毎回**。FREEZE/SEIZE は
  owner 署名すら不要(issuer 単独)。→ **真の self-custody ではなく issuer 常時
  オンライン前提の準中央集権カストディ**。OPS が署名を拒めばそのコインは永久に
  transfer 不能。
- **(b) split/merge 不可 = 1:1 固定**(`mod.rs:52-61`)。全 op が「同一 index への
  単一 successor」しか認証しない(`dr_output_spk_check`)。
- **(c) 各コインは事実上の封緘単位(banknote)**。amount はネイティブ sompi 値
  (`mod.rs:14-27`、KCC-0020 逸脱)。任意額決済は「額面違いを MINT で用意」か
  「BURN→再 MINT」しかなく、いずれも issuer 鍵必須。**口座残高型 ERC-20 とは根本的
  に別物**。
- **(d) N holder スケーリング**: 1 MINT = 1 コイン UTXO、各 UTXO が full covenant
  script(P2SH、`utxo_plurality=2`、実測 script ~1.2–1.3KB / sigscript ~2.7–2.9KB)。
  consolidate 手段が無く、storage mass が線形に積み上がる。
- **(e) 手数料**: 必ず別建て funding UTXO から(covenant コインの価値は削れない、
  value-continuity strict 一致)。
- **(f) epoch の目的**: 鍵失効バインディング(attestation preimage に埋め込み)。
  ただし ROTATE 未実装のため現状 epoch/`role_registry_root` は continuity 比較のみで
  **意味ある検証には未使用**。role 鍵は baked literal。

### 1.3 axis-1 の GAP(重要度順)

- **CRITICAL G0 — 鍵漏洩からの復旧経路が無い**。ROTATE は stub(`dispatch.rs:104`)、
  mint-authority には ROTATE 概念すら無い(0 hit)。**SEIZE の cold 2-of-3 が漏れると
  全コインを owner 同意なし・frozen_flag ゲートなし・pause 不能で強制移転できる**
  (`body.rs:818-1000`、SEIZE は `frozen_flag` を見ない `:936-946`)。しかも唯一の脱出路
  MIGRATE が **同じ seize quorum** でゲートされる(`body.rs:1378-1473`、テスト
  `body.rs:1849-1862`)ため **独立した復旧鍵が存在しない**。mint 側も `mint_pubkey`+
  `cap_authority` 漏洩で無制限インフレが恒久・回復不能。
- **HIGH G1 — 1:1 固定で任意額送金不可**。決済トークンの中核要件を満たさない。
- **HIGH G2 — address blacklist 不在(per-coin freeze のみ)**。OFAC/FinCEN が求める
  「対象アドレスの全資金を即時凍結」が原子的にできない。TRANSFER は successor を
  `frozen_flag==CLEAR` に強制し(`body.rs:373-395`)、新規 MINT コインも CLEAR で
  生まれるため、制裁対象が新たに受け取るコインは自動凍結されない(whack-a-mole)。
- **HIGH G3 — ROTATE 未実装**(G0 の一部)。鍵交換の恒久機構が無く、漏洩時は
  「redeploy + 全コイン個別 MIGRATE(cold quorum 必須)」という重い運用に帰着。
- **HIGH G4 — RAISE_CAP に上限も timelock も無い**。唯一の制約は `new_cap > current_cap`
  (`body.rs:371-390`)。cap_authority が悪意/漏洩なら 1 → `2^63-1` を 1 tx で跳ね上げ
  可能で、holder/規制側が気づく窓が無い。
- **MEDIUM G5 — MINT に per-tx/per-epoch レート制限・recipient allowlist が無い**。
  単一 hot `mint_pubkey`。`role_registry_root` は carry されるだけで mint 時に membership
  ゲートとして参照されない。`MIN_MINT_AMOUNT` は dust floor でオンチェーン強制ではない
  (`mint_authority/attestation.rs:135-146`)。
- **MEDIUM G6 — reserve attestation / net-supply 不在**。running_supply は総発行量のみ
  で BURN を差し引かない(net supply 不明、`attestation.rs:143-146`)。「attestation」は
  本コードでは per-spend 認可署名であって準備金証明ではない(用語衝突に注意)。
- **MEDIUM G7 — global pause 不在**(形式)。OPS 差し止めは TRANSFER のみ停止、
  FREEZE/SEIZE/MINT/RAISE_CAP は別鍵で動き続ける。

**doc 齟齬(要修正)**: (i) `KCC20_STABLECOIN_GAP.md` 表 #10 の「metadata あり
(`token.rs` TokenDescriptor)」は **本 covenant には偽**(`stablecoin/` に TokenDescriptor
参照 0 件、別 contract の話)。(ii) `mint_authority/state.rs:16-29` は RAISE_CAP を
「(stubbed)」と書くが実装済(stale)。

---

## 2. x402 適合(alpha.9)

**エージェント判定**: `exact/standard-native` は **完全適合・真に相互運用可能**。テストは
tautology でなく **load-bearing**(105/105 pass、10 フィールド mutation → `DigestMismatch`、
署名鍵 1 bit 反転 → `BadSignature`、`id` 詐称 → 拒否、sigscript 変更 → id 不変を両方向で
検証)。ただし 2 つの実運用ギャップがある。

### 2.1 適合マトリクス(抜粋)

| 要素 | 状態 | 証拠 | vector 裏取り |
|---|---|---|---|
| canonical JSON(key sort・JS 数値印字・境界) | 適合 | `exact_authorization.rs:57-161`(境界は i64 範囲、2^53 でない :83-100) | Yes(`interop-v1.json`、test :282-288/:391-409) |
| paymentRequirementsHash(SHA-256) | 適合 | `exact_authorization.rs:167-175`、`wire_v2.rs:118` `flatten` で未知 field 保持 | Yes |
| 認可ダイジェスト再計算 + Schnorr 検証 | 適合(旧 HIGH 修正) | `facilitator.rs:543-583`。保持 offer から再計算・id 独立導出・`p2pk_x_only_pubkey(from)` で検証 | Yes(foreign-signer 拒否テスト含む) |
| TransactionID v0(keyed BLAKE2b-256)/ v1(BLAKE3 3 段) | 適合 | `transaction_id.rs:234-256` | Yes(byte-exact) |
| facilitator が id を導出・自称 id 不一致を拒否 | 適合(PR#3 修正) | `transaction_id.rs:263-280`、`facilitator.rs:343-351`。`tx["id"]` を認可に使う経路なし | Yes(lying id 拒否) |
| replay store(txid + per-outpoint) | 適合 | `settle/src/observe/replay.rs`、`facilitator.rs:833-908`(idempotent) | test-backed |
| 402 / PaymentRequirements / network 識別子 | 適合 | `wire_v2.rs:31-32,96-196` | Yes(vendored schema) |
| `X-PAYMENT` → v2 で `PAYMENT-*` に置換 | 正しく追随 | `wire_v2.rs:53-55` | — |
| scheme `exact/standard-native` | **適合・相互運用可** | `scheme_exact.rs:144-226` | Yes(`interop_tests.rs:97-126`) |
| scheme `exact/additive`(KIP-10) | **部分 — wire 適合・実行非互換** | `scheme_exact.rs:228-336`(別 merchant 出力 + continuation)vs upstream(同 script successor + single delta) | wire=Yes / 実行=No(test 自認 :120-123,140) |
| scheme `native` / `kcc20`(generic token_unit) | 自設計に適合(非 interop) | `scheme_native.rs` / `scheme_kcc20.rs`(live TXID あり) | KOB-only |
| scheme `kcc20` を **stablecoin** に | **ブロック/未実装** | 下記 | — |

### 2.2 axis-2 の GAP

- **HIGH G-x1 — stablecoin を x402 で払えない**。`grep stablecoin x402/src` = 0。
  `scheme_kcc20.rs:170,101-104` は recipient SPK を `P2SH(build_token_unit_redeem_script(pk))`
  と **compile-time で導出**するため、body の異なる stablecoin covenant の P2SH を
  構造的に認識できない。加えて stablecoin TRANSFER は issuer OPS attestation 署名を
  要するが client tx builder はそれを作らない。**重要**: これは **ISSUE-6 とは別**で、
  KOB 自身のトークン向けなら **単に未結線**であり upstream を待たず KOB 内で解ける
  (ISSUE-6 は「任意の外部発行トークンを自己記述で受ける」ための upstream 課題)。
- **MEDIUM G-x2 — KIP-10 `additive` が upstream 参照実装と実行非互換**。KOB は
  「別 payment 出力 + continuation index」、upstream は「同一 script successor + 単一 delta
  出力」。参照 x402 wallet が作る tx を KOB facilitator は受理しない(逆も)。wire/schema
  互換を「drop-in 互換」と対外表明すると誤解を生む。in-code では正直に明記済
  (`interop_tests.rs:136-140`、`reservation.rs:9-15`)。
- **LOW G-x3 — doc drift**: `E2E_LIVE_RESULTS.md:777,799,941-945` は `discover_landed_payment`
  の stale-UTXO false-success を未修正と記すが、現 `facilitator.rs:1120-1175` は修正済で
  回帰テスト(`:1666`)も pass。doc を更新すべき。
- **LOW G-x4 — スケール**: `ReservationProvider`(in-memory)/ `ReplayStore`(file)は
  単一プロセス前提でクロスプロセス locking なし。facilitator 水平スケール時は外部ストア要。

---

## 3. KCC-0020 / KCC-0001 適合

**エージェント判定**: 主要点は **verbatim 適合**。残 GAP は **ほぼ全て upstream-blocked**
(仕様側未確定)であり、KOB 実装が直すべき欠陥ではない。

> 監査上の注意: リポジトリに一次仕様 `kcc-0020.md` / `kcc-0001.md` は vendor されて
> いない(`find -iname "kcc-00*.md"` が空)。仕様引用はすべて KOB 自身のドキュメント内
> の逐語引用が出所であり、一次ソースと独立照合はできていない(コード側は直接確認済)。

### 3.1 適合マトリクス(抜粋)

| 要件 | 状態 | 証拠 |
|---|---|---|
| State 符号化(PushExplicit、field order 再帰 lower) | **適合** | `kcc20/state.rs:69-81`・`mod.rs:100-141`、conformance vector test `mod.rs:438-456` |
| P2SH = BLAKE2b(redeem) | **適合** | `settle/src/crypto/p2sh.rs:36-45`(`OpBlake2b` 0xaa) |
| dispatch tag = BLAKE3(sig)[0:4] | **適合** | `kcc20/dispatch.rs:58-65`、vector test :193-200 |
| transfer template 認証(§8.5) | **適合・load-bearing** | `dr_suffix_check` @ `kcc20/transfer.rs:463-467`、敵対テスト `kcc20_contracts.rs:452-490` |
| stablecoin 独自 template 認証(§E CRITICAL) | **修正済** | `dr_suffix_check` @ `stablecoin/body.rs:353`(TRANSFER)/`:597`(FREEZE)/`:862`(SEIZE)、回帰 `stablecoin_contracts.rs:374-388` |
| issuer-authority が KCC-0020 の範囲外か | **正しく範囲外** | 仕様に freeze/seize/issuer/pause は 0 件。bespoke covenant として別 module 実装 |

### 3.2 axis-3 の GAP(全て upstream-blocked / KOB は先行)

- **HIGH G7 — ISSUE-1/11**: `State[]` の int-leaf を kcc-0001 §5.5/§5.6 どおりに符号化
  できない(int は固定幅要求だが実装は可変幅 `PushMinimal`)。KOB は「successor ごとに
  redeem script 全体を blob 引数」で代替(高コストだが安全・engine テスト済)。
  **仕様側の §5.3 addendum を提案する話**であり KOB コード修正ではない。
- **HIGH G6 — ISSUE-6/7**: descriptor に wire format / `ExtensionId` 符号化が無い。
  → **外部発行 KCC20 トークンを x402 で受けられない実害**(`scheme_kcc20.rs:101-110` は
  自 template しか検証できない、`build_token_unit_redeem_script` が compile-time 定数)。
- **MEDIUM G8 — identifier_type reshape**: upstream が「単一 32-byte hash + runtime
  hint」へ倒れつつあり、KOB の PUBKEY-only 前提(8 ファイル・41 非テスト call site)に
  影響。ただし判定は 1 seam(`identifier.rs::emit_ownership_check`)に集約されており
  blast radius は中程度。KOB が推測で先行実装しなかったのは正しい。
- **LOW G8' — ISSUE-19**: §9 の cardinality/coverage を KOB は実質満たす
  (`KCC20_TRANSFER_MAX_N=4` + `OpCov*Count` の `OP_VERIFY`)。残るは `max_participants`
  を descriptor で **外部宣言していない**点のみ(machine-readability の欠落)。

---

## 4. KOB(DEX)適合

**エージェント判定**: **engine 結線ゼロ**。3 独立レベルで確認 —
(i) `grep -rn stablecoin engine/ domain/ settle/` が **0 件**、
(ii) executor が呼ぶ builder は閉じたリスト(`spot::order/oco/swap`・`perp`・`dca`・
`p2pk`)で `contract::stablecoin::*` を一切呼ばない、
(iii) design doc 自身が §10 で「zero integration today」と明記(過去 draft の
「spot covenant がこの descriptor を consume する」を overclaim として自己訂正済)。

### 4.1 統合マトリクス

| DEX 能力 | 状態 | 根拠 |
|---|---|---|
| List / Quote / Match | **不在** | stablecoin covenant を key にする pair/price 経路が無い。`ENGINE_API_DESIGN.md:69`「every pair は TOKEN/KAS」に issuer-authority token の概念なし |
| Settle | **ブロック** | executor に stablecoin op の sigscript builder が無い |
| Deliver to covenant addr | **構造的ブロック** | TRANSFER/FREEZE/SEIZE は successor body を `dr_suffix_check(STATE_HEADER_LEN)` で **同一 template に固定**。DEX 注文 shape に遷移できない。template 変更は MIGRATE のみ(cold 2-of-3) |
| Borrow / collateralize | **不在** | `x402_borrow.rs:18-33` は native-sompi の additive check のみ。asset-type 概念ゼロ |

### 4.2 axis-4 の GAP

- **CRITICAL G10 — engine wiring 皆無 + covenant に「注文になる」遷移が無い**。
  TRANSFER 等は同一 template 固定、MIGRATE は cold quorum 必須。→ **注文の建て = 
  「stablecoin コイン → 板 UTXO」の on-ramp が存在しない**。glue では済まず、
  新しい covenant 分岐(例 `ESCROW`/`LIST` op_type)が要る設計変更。
- **CRITICAL/HIGH G11 — issuer OPS が毎 spend 必須**。engine が自分でこの鍵を持てない
  以上、約定 leg ごとに issuer 署名者への低遅延 out-of-band 経路が要る。これが無いと
  「engine が単独で settle する」前提が全域で崩れる。
- **MEDIUM G12 — mass 予算超過**。N=32 GTC sweep は既に storage mass 449,449/500,000
  (~90%)。stablecoin TRANSFER 1 leg(~90,326)を足すと 539,775 > 500,000 で溢れる。
  `KOB_MAX_GROUPS_PER_CYCLE` は group 数を切るだけで per-tx 構成は縛らない。
- **HIGH G13 — エスクロー座礁(silent death on seize)**。issuer-seize 可能資産を担保に
  取ると、エスクロー中の SEIZE/FREEZE で settle が沈黙死。descriptor による事前判定が
  未実装(§5.2 の座礁リスク)。
- **注意 G-red — `is_freezable` は別物**。板の `is_freezable`(`order_book.rs:165-170`、
  `scanner.rs:428-441`)は **未実装の ZK-precompile freeze 設計**を検出するもので、
  実在の `OpCheckSigFromStack` FREEZE を **検出しない**。統合者は「freeze 対応済」と
  誤認しないこと。

---

## 5. フロー統合性 — mint → pay → deliver は繋がっているか

**判定: 3 つの島。** 貫通経路はコード・script・test・live のどこにも無い。

- 9 op すべて live(4 回、MIGRATE は run2/run4 で **2 回 live**。旧監査の「MIGRATE
  未 live」は stale)。`preflight()` は 9 op 全てで呼ばれ、KIP-9 whole-tx storage-mass
  check + fee-input 検査を実施(FREEZE/SEIZE/MINT/RAISE_CAP が別 fee-input 必須)。
- x402 の「kcc20 scheme」は generic `token_unit` を払う。**stablecoin covenant には
  触れない**(`grep stablecoin x402/src x402/scripts` = 0)。native/exact scheme は
  native KAS。
- **stablecoin harness は coin を x402 facilitator にも DEX にも渡さない**。
- **CLI 表面ゼロ**: `cli/src/lib.rs:3171-3211` の `Commands::Stablecoin` は
  コメントアウト(Phase 2 CLI 移行待ち)。今日 stablecoin を触れるのは demo 鍵ハード
  コードの内部 harness(`kob-stablecoin-e2e`)のみ。
- **HIGH G9 — stablecoin↔x402 seam 不在** / **HIGH G13(再掲)stablecoin↔DEX seam 不在** /
  **MEDIUM G14 — CLI 不在**。

---

## 6. 敵対的健全性 再監査

**方法**: §E の CRITICAL を発見したメタ手法(「branch が **見ない** successor フィールドは
何か?」)を post-fix HEAD に再適用。既存「FIXED」主張は doc を信じず、guard が実バイト
コードに存在し load-bearing か(=除去で attack 再現テストが fail するか)を確認。

### 6.1 既存 FIXED 主張の検証(全て present & 大半 load-bearing)

§E CRITICAL(successor **body**=role 鍵未認証)は **修正済・TRANSFER は load-bearing**。
`dr_input_spk_check`+`dr_suffix_check(STATE_HEADER_LEN)` が TRANSFER(`body.rs:350-355`)/
FREEZE(`:596-599`)/SEIZE(`:861-864`)に配線。frozen_flag domain gate・value continuity・
owner-vs-role 距離 assert・successor `frozen_flag==CLEAR` pin・BURN sink pin・MIGRATE の
cold quorum 排他はいずれも real-engine repro で load-bearing 確認。MIGRATE が body 認証を
免除されるのは設計どおり正しい(任意 template)。

### 6.2 新発見 1(**HIGH / 新規** — 単一 FREEZE 鍵による恒久的コイン破壊)

**穴**: template 認証は successor の **body([75..])** と各 **payload 範囲**は固定するが、
state header 内の **5 つの push-opcode バイト**(`0x20,0x01,0x20,0x01,0x04` @ offset
0/33/35/68/70)を **一切認証しない**。`body.rs:135-138` は `*_PAYLOAD_OFFSET` だけを import し、
`grep OPCODE_OFFSET body.rs` は **0 件**(発行者側で確認済)。`dr_suffix_check` は `[75..]` しか
見ず、各 `dr_field_extract` は payload 範囲しか見ないため、これら 5 バイトは spender が任意値に
できる(covenants 有効時は minimal-push 強制も無効 `txscript/lib.rs:627`)。

**攻撃**(capability = **FREEZE role の単一鍵のみ**、owner 同意・quorum 不要):
honest な successor を作り、opcode バイト 1 個(例 offset 70 の `0x04`)を別値に破壊 →
全オンチェーン検査(`dr_output_spk_check`・payload 等価×4・value continuity・domain gate・
FREEZE 署名)を通過(どれも byte 70 を見ない)→ tx 確定。その successor コインの P2SH は
破壊された `new_rs` にコミットしており、後で **誰が**(owner/FREEZE/SEIZE quorum/MINT)
spend しようとしても header の push が想定と違う長さで parse され、dispatch の固定 stack 深さ
(`OP_TYPE_TAG_DEPTH=5`)が崩れて **実行不能 = コインが永久に spend 不能**。unfreeze も
SEIZE 救済も BURN も効かない(P2SH commitment は厳密で他バイトは hash が合わない)。
`running_supply` は BURN でしか減らないので、破壊されたコインは **outstanding/backed のまま
残り供給計上がずれる**。

**なぜ設計の読み違いでないか**: **同じコードベースが同じ穴を他所で塞いでいる** —
`mint_authority/body.rs:338-346`(RAISE_CAP「Step 4: push-opcode sanity check, new_rs[9] must
still be 0x08」)・`:593-600`(MINT)・`spot/dca.rs:36`(「Verify push prefix at byte 144==0x08」)。
stablecoin の TRANSFER/FREEZE/SEIZE だけがこの sibling パターンを **貰い損ねている**。
これは §E CRITICAL(body 認証)の **一層下**にある「誰も見ないフィールド」。

**深刻度の位置づけ**: FREEZE は design 上「policy-only・可逆・非カストディ」の低privileged
分岐のはずが、この穴により **単一 hot 鍵で不可逆な資金破壊**ができる=文書化された脅威
モデルの外。盗難ではなく破壊/griefing だが、単一鍵・不可逆・cold quorum 不要という点で
実質 CRITICAL 級。

**検証状態**: 構造前提(opcode バイト未認証・sibling に正しい実装が存在)は発行者側で
grep/offset 突合により **確認済**。exploit の実行(破壊コインが実際に spend 不能になること)は
read-only 監査のため **live TxScriptEngine で未実行**。着手時は PoC テスト先行を推奨。

**修正**: TRANSFER/FREEZE/SEIZE の各 header opcode 位置に `dr_field_extract(OFFSET,OFFSET+1)`
+ literal `OpEqual`+`OpVerify` を追加。最安手は **既存の各 payload extract を 1 バイト前へ
広げ**(`[OPCODE_OFFSET..PAYLOAD_END)` を `[canonical_opcode]||value` と比較)、新規 opcode
ゼロで塞ぐ。`mint_authority::body` の Step 3/4 idiom をそのまま踏襲。

### 6.3 新発見 2(MEDIUM / 回帰カバレッジ欠落)

§E の role-swap guard は FREEZE(`body.rs:596-599`)/SEIZE(`:861-864`)にも配線済だが、
**TRANSFER にしか attack-repro テストが無い**(`FreezeCfg`/`SeizeCfg` に
`successor_role_seeds` レバーが無く、`freeze/seize_successor_swaps_role_set_rejected` が
不在)。guard バイトは present なので現時点で live 脆弱性ではないが、depth 演算の refactor で
FREEZE/SEIZE だけ CRITICAL が再発しても CI が捕まえられない。**修正**: 2 分岐に
`transfer_successor_swapping_the_role_set_rejected` 相当のテストを追加。

### 6.4 追加の doc 齟齬

`body.rs:120-131` の module doc は「TRANSFER は successor の frozen_flag を比較しない」と
記すが、実コード `body.rs:373-393` は `successor.frozen_flag==CLEAR` を pin 済。コードが正・
コメントが stale(要更新)。

### 6.5 掃討して問題なしと判定した角度

cross-op/dispatch 混同(op_type は全 preimage に束縛・dispatch 末端が hard `OpVerify`)・
attestation の coin/spend 跨ぎ replay(covenant_id+outpoint+op_type 束縛)・MIGRATE scope・
sig_op_count/sighash 整合・mint-authority linear UTXO/epoch/mass-dust。いずれも clean。

---

## 7. GAP をどう埋めるか — 深掘り設計

GAP を「**発行体権限を無くす**」方向で埋めてはならない。規制ステーブルコインは定義上
issuer が freeze/seize/mint を握る中央集権資産である(§3.4 でフレーム統一済)。真の
課題は **「その権限を UTXO/BlockDAG 上で並列性と決済性を殺さず執行する参照方式の選択」**。
以下、レイヤ別に実装形を設計する。

### 7.1 決済トークン化(G1 / 任意額送金)— 最優先・自己完結

現状の 1:1 封緘単位は banknote であって決済トークンではない。**N:M transfer(split/merge)**
を実装する:

- `kcc20/transfer.rs:130` の `KCC20_TRANSFER_MAX_N=4` パターン(固定上限 N で unroll +
  `OpCovInputCount`/`OpCovOutputCount` の `OP_VERIFY` 境界)を stablecoin covenant に移植。
- **保存則 Σin.amount == Σout.amount** を複数入出力で検証。amount は native-sompi 方式を
  継続(§5.1 で決着済)なので、各 output の sompi 値の総和で検算できる。
- 各 successor には従来どおり `dr_suffix_check` で body 固定(role 鍵不変)を維持。
- 効果: 任意額決済・お釣り・consolidate(G-d の storage mass 線形増を緩和)が同時に解決。
- 注意: MINT の anti-backdoor 再構成(`mint_authority/body.rs:648-702`)は 1 出力前提
  なので、batch mint を足すなら出力ごとに繰り返し script size 線形増を許容する。

### 7.2 コンプライアンス層(G2 blacklist / G5 pause / G4 reserve)

Kaspa は **reference input を持たない**(`consensus/core/src/tx.rs:254`、introspection は
自 tx の input しか読めない)。CIP-113/Nervos-RCE の「共有 denylist を全 transfer が
read-only 参照」は Kaspa では 1 ブロック 1 転送に縮退するため **移植不可**。3 択:

1. **address blacklist(G2)= SMT root 焼き込み方式**(Kaspa 固有解)。denylist を
   Sparse Merkle Tree 化し root を各コインの state(`role_registry_root` の後継 field)に
   焼く。送金時に受取人の **non-membership proof** を sigScript で提示、covenant が自 state
   の root に対し検証。共有参照 UTXO が消え **並列性ボトルネックゼロ**。代償は **反映ラグ**
   (root 更新は各コインが次に動くまで届かない)。即時性が要るケースは per-coin FREEZE で
   補完(併用)。
   - **より安価な運用代替**: TRANSFER は既に全件 issuer OPS gate なので、**OPS 署名者が
     署名前に受取人を sanctions 照合**すれば実質 address 単位の遮断になる(即時・オンチェーン
     露出なし)。indexer で対象アドレスの全保有コインを列挙し **一括 FREEZE バッチ**を出す
     runbook を併設。まずこれ、構造対応(SMT)は次段、が現実的。
2. **global pause(G5)**: `§11-iv` の判断どおりプロトコル変更は避け、OPS/FREEZE/MINT/
   cap_authority の各署名者を **1 スイッチで同時停止**する運用 kill-switch を runbook 化。
   OPS 停止だけでは TRANSFER しか止まらない点を明示。
3. **reserve attestation(G4)**: issuer が準備金監査ハッシュに署名し **OP_RETURN で anchor**
   する軽量 tx を追加(covenant 変更不要)。net supply は BURN sink への spend を indexer で
   追跡し `running_supply − 累積burn` を公表、または burn-receipt を mint_authority が定期
   消込む。

### 7.3 鍵管理と鍵漏洩復旧(G0 CRITICAL / G3 ROTATE)— セキュリティ最優先

現状の最大の穴は「seize quorum が漏れると全額奪取でき、脱出路 MIGRATE も同じ quorum で
守られる=独立復旧鍵ゼロ」。埋め方:

- **独立した復旧 quorum を分離する**。MIGRATE(と ROTATE)を `seize_pubkeys` とは
  **別の cold key set** でゲートし直す。これで「seize 鍵漏洩 ⇒ 復旧不能」の連鎖を切る。
  現状は両者が同一で、テスト `body.rs:1849-1862` もそれを固定してしまっている。
- role 鍵を **baked literal → reveal-and-verify against `role_registry_root`** 方式へ変更
  (コスト概算 +160B/tx、文書化済)。これで `role_registry_root`/`epoch` が「continuity
  比較のみ」から **意味ある検証**に格上げされ、ROTATE が実装可能になる。
- ROTATE 分岐(3-of-5 cold multisig 等、seize とは別鍵)を配線し stub を除去。
  mint-authority 側にも ROTATE を **新規設計**する(現状 概念ゼロ)。
- 移行までの緩和: 鍵漏洩時の **SEIZE→(issuer 管理下 owner 化)→MIGRATE** 2 段階強制移行を
  公式 runbook 化し、cold quorum を air-gap・複数カストディで事前プロビジョニング。

### 7.3b 発行制御の締め付け(G4 RAISE_CAP / G5 MINT)

- **RAISE_CAP に上限と timelock**。`new_cap <= current_cap * K`(board 承認の K)を
  オンチェーン強制し、さらに DAA-height introspection(既に `spot::dca` で使用)で
  「pending cap + 発効 height」を書き、発効までは MINT が旧 cap を見る遅延型にする。
- **MINT に epoch 予算**。lifetime cap とは別の per-epoch mint 上限 field(DAA 境界で
  リセット)を既存 cap check と同じ方式で強制。recipient を `role_registry_root`
  membership でゲート(現状 carry only)。dust floor はオンチェーン化を検討。

### 7.4 統合層 — 3 つの島を 1 本にする(最難関)

#### (A) descriptor wire format(G6/ISSUE-6)= 要石

これが解けると **外部トークン受入と x402 kcc20 scheme の両方が同時に解ける**。
`KCC20_ISSUES.md:529-546` の wire format 案を **upstream に提案しつつ**、KOB 側に
`descriptor.rs` の `encode`/`decode` を実装(prefix/suffix/extended_state_layout/
`ExtensionId` を含む)。issuer-authority extension の宣言(freeze/seize 可否フラグ)も
この wire に載せる → §7.4(C) の DEX 事前判定に直結。

#### (B) stablecoin ↔ x402(G-x1)— upstream を待たず今すぐ着手可

これは **ISSUE-6 とは別問題**で KOB 内で完結する。(1) `scheme_kcc20.rs` の recipient SPK
導出を「compile-time の `P2SH(build_token_unit_redeem_script(pk))`」から
**caller 宣言の redeem-script/P2SH template**(stablecoin の実バイトコード)を受ける形に
一般化、または stablecoin 専用 verifier を新設し TRANSFER 分岐の出力/state-continuity を
検証。(2) client tx builder が **owner 署名 + issuer OPS attestation** を含む TRANSFER spend
を組めるようにする。ただし stablecoin TRANSFER は bare 署名でなく OPS attestation 必須なので、
facilitator/online issuer oracle が **各支払いを co-sign** できる必要がある(§(C)2 の G11 と
同根の運用依存)。ISSUE-6 が要るのは「**任意の外部発行**トークンを自己記述で受ける」場合のみ。

#### (C) stablecoin ↔ DEX(G10/G11/G12/G13)

1. **新 covenant 分岐 `ESCROW`/`LIST`(G10)**: TRANSFER に似るが、successor を「**同一
   template** ではなく **DEX 注文 template**」へ継続することを認可する op_type を新設。
   これが無い限り「stablecoin コイン → 板 UTXO」の on-ramp は存在しない。
   - 重要: successor-linearity 自体は batch settlement の atomicity と矛盾しない
     (per-coin・共有 state なしの SEIZE/FREEZE/TRANSFER 設計はむしろ並行 settle に好適、
     §3.4)。矛盾しているのは **「注文 shape への遷移が無い」一点**。
2. **issuer OPS 経路(G11)**: DEX の約定 leg ごとに issuer 署名者へ低遅延 attestation を
   取りに行く out-of-band チャネル、または **DEX-transfer を issuer が事前一括認可**する
   attestation 型(「この covenant-id 系列の板遷移を許可」)を設計。engine は issuer 鍵を
   持てないので、ここは avoid できない構造要件。
3. **descriptor 事前判定(G13)**: (A) の wire で宣言された issuer-authority/seize フラグを
   **spot covenant が注文受付時に参照**し、拒否 / リスク開示 / fail-close を選択。
   エスクロー中 seize を検知して沈黙死させず巻き戻す settle 経路を明示設計。
4. **mass headroom 予約(G12)**: stablecoin leg を含む cycle は batch サイズを縮小するか、
   per-cycle group 構成に headroom 予約ロジックを追加(現状 `KOB_MAX_GROUPS_PER_CYCLE`
   では不足)。
5. **異形遷移への防御(ISSUE-15 恒久対策)**: leader が sibling state を固定オフセットで
   読む前提を、witness/descriptor 由来の shape 記述に基づく分岐へ。

#### (D) CLI 表面(G14)

`Commands::Stablecoin`(`cli/src/lib.rs:3171`)を新 API に移行し全 op を subcommand 化
(= Liquid 相当の UTXO 制御)。offline 再検証 → testnet-10 の順。

### 7.5 upstream(KCC)へ出すべきもの

- ISSUE-1/11 の §5.3 addendum(state-payload 8-byte int を record-array leaf にも適用)。
- **ISSUE-6 descriptor wire format**(要石、§7.4(A))。
- ISSUE-19 の `max_participants` descriptor field。
- identifier_type reshape の追随(単一 32-byte hash + runtime hint への移行を監視、
  `identifier.rs::emit_ownership_check` の 1 seam で吸収)。

### 7.6 実装順序(推奨)

00. **§6.2 header opcode 認証(新 HIGH)を塞ぐ**。TRANSFER/FREEZE/SEIZE の各 payload
    extract を 1 バイト前へ広げ opcode を固定(新規 opcode ゼロ)。単一 FREEZE 鍵による
    恒久破壊を断つ最優先の一手。**先に PoC テストで exploit を live 確認**してから修正。
    同時に §6.3 の FREEZE/SEIZE role-swap 回帰テストも追加。
0. **§7.3 復旧 quorum 分離(G0 CRITICAL)**。seize と別鍵で MIGRATE/ROTATE をゲートし直す。
   全額奪取からの復旧不能を断つ最優先の安全対策(小さな変更で効果大)。
1. **§7.1 N:M transfer**(決済トークンとして成立させる。自己完結・依存なし)。
2. **§7.3b RAISE_CAP 上限/timelock + MINT epoch 予算**(発行制御の締め付け、covenant 変更小)。
3. **§7.2-1 運用 blacklist + §7.2-3 reserve anchor**(コンプラの最低線)。
4. **§7.4(B) stablecoin↔x402 結線**(ISSUE-6 非依存、KOB 内で完結)。
5. **§7.4(A) descriptor wire**(要石。外部トークン + 任意 KCC20 の x402 受入を解錠)。
6. **§7.4(C) ESCROW 分岐 + descriptor 事前判定**(DEX 上場の on-ramp と座礁対策)。
7. **§7.3 ROTATE 恒久化 + §7.4(D) CLI**(鍵管理の恒久化と利用者表面)。
8. **§7.2-1 SMT root blacklist**(構造対応、反映ラグ受容できる段階で)。

---

## 8. 出典 / 監査ログ

- 一次コード: `kob/core/src/contract/stablecoin/`(+`mint_authority/`)、`kob/core/src/contract/kcc20/`、`kob/x402/src/`、`kob/engine/`・`kob/domain/`・`kob/settle/`。
- 既存 doc: `STABLECOIN_ROBUST_DESIGN.md`・`STABLECOIN_AUDIT_2026-07-20.md`(§E CRITICAL)・`STABLECOIN_E2E_LIVE.md`・`KCC20_STABLECOIN_GAP.md`・`KCC20_ISSUES.md`・`X402_STATUS.md`・`BATCH_LIMITS.md`・`ENGINE_API_DESIGN.md`。
- 監査体制: Sonnet エージェント 6 体並列(機能完全性×2 / KCC 適合 / x402 適合 / KOB 適合 / 敵対的健全性 / フロー統合性)+ 発行者側 file:line 相互検証。テストは HEAD で green(x402 105 passed 等)。
- 全 6 軸確定。**唯一の未 live 検証項目 = §6.2 の header-opcode exploit**(構造前提は確認済、実行破壊は PoC 待ち)。次アクションは §7.6 の順序 00 番から。

---

## 9. 実装ログ(§7.6 の充填進捗、2026-07-20 開始)

> 実装は §7.6 の推奨順で進行。各項目は実 `TxScriptEngine` 回帰テスト green を landing gate とする。
> ビルドは `CARGO_TARGET_DIR=/root/kob-target`(exec fs、/storage は noexec)、編集後 `touch` 必須(sdcardfs stale mtime)。

### 監査後是正(00/0/1/2 を landing 後の敵対監査、3面 Sonnet + 発行者 file:line/PoC 裏取り)
実装済み 4 項目に対し **branch が見ないフィールドは何か?** メタ手法 + fund-security 観点で再監査。cross-item
リグレッション(dispatch 6→8・mint state 18→45 relayout・N:M op_type 追加)は **3面とも clean**(engine 105 独立再走含む)。
発見と処置:

- **🔴 CRITICAL(N:M delegator OPS-gate bypass)— 修正済・push 済(`a1d71f46`)**。delegator(0x08)は owner 署名のみで
  通り、OPS attestation も「leader が実在するか」の検証も無い(per-input 検証ゆえ position 0 の op_type は他入力から不可視)。
  攻撃= position 0 に単一 TRANSFER(自コイン+narrow OPS)を囮、position 1 に delegator を乗せて別コインを OPS 承認なしで
  covenant 外へ。修正= **全単一枝(TRANSFER/FREEZE/SEIZE/BURN/MIGRATE)に `OpCovInputCount(own cid)==1` を強制**
  (net-zero)→ 同一 lineage の多入力 spend は必ず leader/delegator 経路(position 0=leader が全 sibling を会計・OPS attest)に
  一本化。**merge 温存**(利用者提案の方式、私の split-only 案より優)。回帰テスト `transfer_nm_delegator_decoy_attack_is_rejected`
  で囮攻撃を実 engine 再現し、guard 有効で reject・無効で ACCEPT(=攻撃実在)を確認。
- **🟠 HIGH(ACTIVATE_CAP timelock を hot MINT 鍵で無限 grief)— 修正中**。MINT が self-continue UTXO の block_daa_score を
  毎回更新→CSV 時計が reset され、cap-authority 承認の raise を hot 鍵単独で恒久ブロック可。修正= **activation height を state に
  焼く**(`pending_since_daa` 新設、ANNOUNCE が OpTxInputDaaScore を刻印、MINT は不変 carry、ACTIVATE は
  `pending_since_daa + min_delay <= now` を state 参照で判定)→ MINT は窓を後ろへ押せない。要 compromised hot 鍵ゆえ影響は限定だが
  G4 の窓保証を破るため修正。
- **🟡 MEDIUM(owner ≠ role 鍵を on-chain 未強制)— 記録・on-chain 強制は defer**。genesis assert のみで per-spend 未検証。
  ただし **発行者が全経路をトレースし具体 exploit 無しと確認**: owner==role 鍵でも各操作は依然その role 鍵自身の権限を要し
  (MIGRATE は 2 recovery 秘密が依然必要、owner==role は「発行者が自コインを所有」に帰着)、盗取・越権に至らない。role-hygiene の
  defense-in-depth。honest deploy は genesis assert が防ぐ。on-chain per-spend 強制(8-9 baked 鍵との不一致検査×4枝)は
  コスト対効果で次段へ。
- **🟡 MEDIUM(N:M `outputs_digest` が SPK のみで amount 非束縛)— 記録**。OPS 単一署名は「どの SPK が group 成員か」は縛るが
  各 successor の受領額は縛らない。ただし acc==0 conservation(実オンチェーン値・正確)+ 全署名者の SIGHASH_ALL が最終額を固定するので
  script 単独では不正取得不能。value-split の正しさは owner 署名側の性質であって OPS attestation の性質でない旨を明記(過信防止)。
- **🟡 MEDIUM(G5 epoch 予算は固定窓ゆえ境界跨ぎで最大 2×burst 可)— 記録**。hard cap(current_cap)は不変ゆえ上限突破でなく
  throttle 平滑性の弱み。sliding-window 化は高コストゆえ限界として明記。
- 安手修正(mint 側、CSV 修正と同エージェントで実施中): `build_mint_authority_body` に pairwise-distinct assert 複製 /
  genesis `pending_cap==current_cap` assert / `min_activation_delay_daa` 上限 assert / MINT module doc の stale layout 訂正。

### ✅ 00. header opcode 認証(§6.2 新 HIGH)— **完了・live 確認済**
- 修正: `stablecoin/body.rs` に共有ヘルパ `emit_header_opcode_authentication(b, new_rs_depth)` を新設し、
  TRANSFER(new_rs depth 3)/FREEZE(depth 6)/SEIZE(depth 7)の各枝から呼ぶ。5 つの header push-opcode
  バイト(offset 0/33/35/68/70 = `0x20/0x01/0x20/0x01/0x04`)を canonical 値に対し `dr_field_extract`+`OpEqual`+
  `OpVerify` で固定。各チェックは stack net-zero(`mint_authority::body` の Step 3/4 idiom を踏襲)。**単一ヘルパ化で
  3 枝の再ドリフトを構造的に防止**(本バグの発生原因=枝ごとの sibling パターン貰い損ね を封じる)。
- **exploit を live で確認**: guard を一時無効化して corrupt-successor テストを実行 → TRANSFER/FREEZE/SEIZE の
  3 枝すべてで **"the transfer was ACCEPTED"**(=§8 が唯一の未 live 項目としていた header-opcode 破壊が実在すること
  を実 engine で確認)。guard 有効化で同テストは全 REJECT(`VerifyError`)。
- テスト追加(`stablecoin_contracts.rs`): 5 offset sweep × 3 枝の corruption 拒否テスト + §6.3 の
  FREEZE/SEIZE role-swap 回帰テスト(`FreezeCfg`/`SeizeCfg` に `successor_role_seeds` レバー新設)。
- doc 修正: §6.4 の `body.rs:120-131` module doc(「TRANSFER は frozen_flag を pin しない」stale)を訂正。
  §1 の `KCC20_STABLECOIN_GAP.md` #10 metadata 主張(stablecoin covenant には偽)を訂正。
- **結果: kob-core 全 798 テスト green(stablecoin 54 = 旧 49 + 新 5)、crate 横断リグレッションなし。**

### ✅ 0. 復旧 quorum 分離(G0 CRITICAL)— **完了・検証済**
- 独立 `recovery_pubkeys: [[u8;32];3]` cold set を新設し MIGRATE をこれでゲート(SEIZE の `seize_pubkeys` と分離)。
  build 時 pairwise-distinct assert を 6→9 keys に拡張(`build_stablecoin_body`/`build_stablecoin_redeem_script`)。
  mint_authority 側(`build_fixed_mid`/`build_mint_authority_body`/`build_mint_authority_redeem_script`[role-key array 9→12]/
  `build_emitted_coin_redeem_script`)にも thread。CLI harness(`kob_stablecoin_e2e.rs`)は既存の demo `recovery`
  フィールドとの名前衝突を避け `migrate_quorum` として配線。SEIZE/MIGRATE の preimage domain 分離(op_type 0x02/0x06)は
  既に正しく、変更不要(defense-in-depth を追加)。ROTATE は deferred のまま。
- **核心の回帰テスト green**: `migrate_rejects_genuine_seize_quorum_signatures`(本物の SEIZE 署名者[81/82/83]が MIGRATE を
  認可できないことを実 engine で確認)。`recovery_quorum_keys_baked_via_checksigfromstack_in_migrate_branch`(RECOVERY baked・
  SEIZE/OPS non-baked)。**結果: kob-core 全 1021 テスト green(発行者が独立再実行で裏取り)、CLI バイナリ compile clean。**

### ✅ 1. N:M transfer(G1)— **完了・検証済**
- leader/delegator 分割(新 op_type `0x07 TRANSFER_NM` + `0x08 DELEGATOR`、dispatch 6→8 rung)。
  `OpTxInputAmount(0xbe)`/`OpTxOutputAmount(0xc2)` + `OpCovInput/OutputCount/Idx` で native-sompi の `Σin==Σout` を on-chain 強制
  (consensus 変更不要)。leader が group 全体を bookkeeping、delegator は self-authorize + 自身の frozen gate のみ。
  group-digest 単一 OPS attestation(111B preimage)、`MAX_N=4`。**item-00 の opcode 固定を successor ごとに組込済**。
  scope=同一 MINT lineage 内(covenant_id 単位)。既存枝(0x00-0x06)の body は byte 不変(dispatch ladder wrapper のみ拡張=
  新規 deploy の P2SH shape 変更、既存 coin は自身の baked script で不変)。
- **テスト 11 本 green**(2in-1out merge / 1in-2out split-change / all-slots-active / conservation 違反 reject /
  cardinality 超過 reject / successor role-swap・frozen-set reject / delegator frozen-input・leader なりすまし reject /
  header-opcode tamper reject[item-00 を TRANSFER_NM 内で再 guard] / attestation replay reject)。
- **結果: kob-core 全 1038 テスト green(発行者が独立再実行で裏取り)。** depth `+1`(dr helper の第2引数)と harness の
  sig_op_count/sighash 整合の 2 点が実装中に要ピン(実 engine TDD で解決)。

### ✅ 2. RAISE_CAP 上限/timelock + MINT epoch 予算(G4/G5)— **完了・検証済**
- state 再レイアウト(field-ownership: MINT-owned prefix + cap-authority block、`STATE_HEADER_LEN` 18→45、
  running_supply@0/minted_this_epoch@9/epoch_start_daa@18/current_cap@27/pending_cap@36)。`mint_authority/state.rs:16-29` の
  「(stubbed)」stale コメントも訂正(§1 doc 齟齬)。
- **A.1 ceiling**: `new_pending_cap <= current_cap * K`(checked `OpMul`、overflow で fail-closed abort、K=`cap_raise_multiplier_k` 定数 k>=2)。
- **B.3 dust floor**: `mint_amount >= MIN_MINT_AMOUNT` を on-chain 化。
- **B.1 MINT epoch 予算**: `minted_this_epoch`+`epoch_start_daa` を `OpTxInputDaaScore` 境界で reset、`<= epoch_mint_budget` を on-chain 強制
  (MINT に stack-shape 復元型の self-contained 挿入)。
- **A.2 timelock**: 二相 ANNOUNCE_CAP(0x01、旧 RAISE_CAP)/ACTIVATE_CAP(0x02 新・permissionless・sig_op_count=0)、
  CSV(`OpCheckSequenceVerify`)で実 UTXO の `block_daa_score` に対し `min_activation_delay_daa` を強制(stale-gaming 耐性)。dispatch 3-way 化。
  ANNOUNCE は pending_cap のみ書換(current_cap は middle-lock)、ACTIVATE は pending→current 昇格 + sentinel reset。
- **recipient allowlist は operational 層に defer**(role_registry_root は category error)。
- **結果: 全 3 stage green、kob-core 全 1055 テスト green(発行者が独立再実行で裏取り)+CLI compile clean。**
  新 mint_authority テスト +14(dust/epoch-budget/ceiling/ANNOUNCE_CAP 敵対 suite/ACTIVATE_CAP 昇格・premature-sequence reject)。
- **timelock = CSV(`OpCheckSequenceVerify` 0xb1)を採用**(CLTV でない): CSV は consensus の `check_sequence_lock` が
  **その UTXO 自身の実 `block_daa_score`(改竄不能)** で強制 → 「announce→N block 待ち→activate」に stale-gaming 耐性。
  二相 ANNOUNCE_CAP/ACTIVATE_CAP に分割(新 op_type、dispatch 3-way 化)。**新 state field 不要**(UTXO の confirm height が anchor)。
- **ceiling = `OpMul` の checked 意味論**で `new_pending_cap <= current_cap * K` を強制(i64 overflow で fail-closed abort、加算迂回不要)。
- **G5 recipient gate = role_registry_root は不可(category error: governance role commitment であって recipient 集合でない)**。
  → **on-chain recipient allowlist は operational 層に defer**(MINT attestation 署名者が拒否)。今回は **epoch 予算 + dust floor のみ on-chain**。
- epoch 予算 = `OpTxInputDaaScore` を「現在」proxy(ここでは stale-safe)、MINT に self-contained 挿入。dust floor = `MIN_MINT_AMOUNT` on-chain 化(trivial)。
- 複雑度: A.1 ceiling + B.3 dust = 低(mechanical)/ B.1 epoch 予算・A.2 timelock = medium-high(算術密・dispatch arity 変更、byte-exact テストで gate)。推奨順 A.1+B.3 → B.1 → A.2。
