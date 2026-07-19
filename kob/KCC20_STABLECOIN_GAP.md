# KCC-0020 / KCC-0001 ステーブルコイン機能ギャップ統合レポート

規制準拠ステーブルコイン(USDT/USDC 型)の必須機能セットを、KCC-0020(Fungible
Token Covenant Specification)/ KCC-0001(Covenant ABI)の現状と照合し、UTXO /
BlockDAG モデル固有の実装上の緊張点まで含めて整理する。目的は「KCC に何が足り
ないか」を一目で把握できるようにし、Manyfest の minimal-core 設計思想を尊重した
上で、ステーブルコインという具体用途に必要な named extension を建設的に提案する
ことにある。

本レポートは 2 つの完了済み調査を統合する:

- **調査B** — 規制ステーブルコイン(USDT/USDC + GENIUS Act / MiCA / NYDFS)が
  実装する必須機能セット。
- **調査A** — UTXO チェーン上で発行体制御を実現する 6 類型(A〜G)と、その限界。

KCC/KOB 側の記述はすべて仕様原文(`kcc-0020.md` / `kcc-0001.md`)と KOB 実装コード
(`kob/core/src/contract/kcc20/`, `kob/core/src/contract/token.rs`)を file:line で
裏取りしている。未実証の先行例(Cardano CIP-113、Nervos RCE)は必ず「未実証」と
明記する。

---

## 目次

1. [要旨](#1-要旨)
2. [機能マスターリスト × KCC 照合表](#2-機能マスターリスト--kcc-照合表)
3. [各 gap の深掘り(freeze / seize / supply-cap)](#3-各-gap-の深掘りfreeze--seize--supply-cap)
4. [KCC への提案](#4-kcc-への提案)
5. [KOB にとっての含意](#5-kob-にとっての含意)
6. [出典](#6-出典)

---

## 1. 要旨

**必要な機能セット(調査B)。** 規制準拠ステーブルコインが consensus / 契約レベル
で持つ機能は、大きく (a) 供給管理(mint / burn を準備金 1:1 に連動)、(b) 発行体
コントロール(freeze / blacklist、seize / 没収、pause)、(c) 償還権と準備金照会、
(d) ロール分離(USDC は masterMinter / pauser / blacklister / rescuer を別鍵に分
離)に分けられる。特に freeze / seize は「あれば良い」ではなく、GENIUS Act 系の
2026 年 FinCEN / OFAC NPRM が発行体に対して「特定資産を block / freeze / reject
する技術的能力」を明示的に義務化しており、これを持たない資産はメジャー発行体から
の USD ペッグ発行の実務要件を満たさない。

**KCC の現状(裏取り済)。** KCC-0020 は意図的な minimal core であり、定義するのは
(1) 拡張可能なトークン state ヘッダ(`owner_identifier` / `identifier_type` /
`amount` / `extended_state_digest`)、(2) `transfer` / `transfer_delegator` の 2
エントリポイント、(3) descriptor、(4) optional extension 宣言機構の 4 点に限られ
る。正式に定義された extension は **Borrowed Receive v1 の 1 つだけ**で、これは
受取 UTXO の再利用という利便性機能であって発行体コントロールとは無関係である。
`kcc-0020.md` / `kcc-0001.md` 全文に対して `freeze` / `blacklist` / `pause` /
`seize` / `issuer` / `authority` / `compliance` を grep しても**一致は 0 件**で
ある(`KCC20_ISSUES.md §5.1` で既報)。

**これは欠陥ではなく scope。** 著者 Manyfest は minimal-core 主義を明言しており、
mint / burn / freeze / seize / supply-cap を core に置かないのは設計判断である。
したがって本レポートの主張は「KCC-0020 に freeze が無いのはバグだ」ではなく、
「**ステーブルコインという具体用途では、core を汚さず named extension として標準化
すべき機能群が明確に存在する**」という建設的フレームである。実際、Manyfest 自身
がスレッド #8 で issuer policy の必要性と「global state utxo を強制するトークン」
という暫定案を示し、Max143672 が「独立 spending branch」「two-phase transfer」と
いう緩和案を提示しており、議論の素地は既にある。

**ギャップ件数。** 第 2 章の照合表で対象とした 15 機能のうち、規制優先度が
**MUST の機能は 8 件(mint / burn / supply-cap / freeze / seize / redemption /
role-separation / reserve-attestation)、その 8 件すべてが KCC-0020 の core にも
唯一の定義済み extension(Borrowed Receive)にも存在しない**。SHOULD は 3 件
(pause / upgradeability / rescue)、OPTIONAL / 条件付き禁止が allowlist を含む
残りである。ただし redemption と reserve-attestation は本質的にオフチェーン / 法
的レイヤの機能であり、必要なのは「オンチェーンのフック」であって covenant による
完全実装ではない。純粋にオンチェーン covenant 拡張を要する MUST gap は mint /
burn / supply 整合性 / freeze / seize / role-separation の 6 件に集約される。

**最重要の設計上の緊張点 = 並行性。** 調査A の結論は明確である。UTXO の自己主権
(permissionless 性)を保ったまま freeze を実運用した例は事実上ゼロで、UTXO ネイ
ティブな唯一の解はパターン D(オンチェーン registry cell + covenant introspection、
Cardano CIP-113 / Nervos xUDT+RCE)だが、**両者とも本番未実証**である。しかも
パターン D はグローバル state を持つ 1 個の cell が全 transfer の参照点になるため、
その cell が並行性のボトルネックになる。これは BlockDAG による高い並列性を売りに
する Kaspa にとって最も痛い緊張点であり、Manyfest の「global state utxo」案も
この問題をそのまま抱える。しかも Kaspa には **reference input(consume せず read-only
で UTXO を参照する Cardano CIP-31 相当)が存在せず**(`consensus/core/src/tx.rs:254-269`、
introspection opcode は全て「このトランザクションの input」しか読めない)、共有
denylist UTXO を参照するには spend が要る。したがって CIP-113 をそのまま移植すると、
全転送が同じ denylist を二重支出で奪い合い **1 ブロック 1 転送に縮退**し、ボトルネック
は CIP-113 本体より深刻になる(第 3.4 章)。Kaspa 固有の解は denylist の SMT root を
各コインに焼き込み共有 UTXO を消す方式だが、凍結更新に反映ラグが伴う。KOB / KCC への提案の核心は、**freeze/seize をグローバル
state 参照から切り離し、per-UTXO 凍結フラグ + 独立 `issuer_seize` エントリポイント
に閉じ込めることで、無関係な transfer 同士の並行性を壊さない**設計を named
extension として標準化することにある。

**第3の道 — オラクル attestation はボトルネックを構造的に回避する。** 調査A の
「UTXO 上で発行体 freeze を permissionless 性を保ったまま実運用した例は事実上ゼロ」
という結論は、パターン D(registry cell 参照)を軸にした場合の話である。Kaspa には
`OpCheckSigFromStack`(0xd7、`crypto/txscript/src/opcodes/mod.rs:1634`。ECDSA 版
`OpCheckSigFromStackECDSA` 0xd8 は `:1645`)という、**トランザクション sighash とは
無関係に、スタック上の任意 32byte メッセージハッシュ+署名を検証できる opcode** が
既に実装されている。これを使えば、発行体(オラクル)が「この受取人は clean」「この
転送を許可する」という attestation に署名し、転送者がそれを sigScript に載せ、転送
covenant が `OpCheckSigFromStack` でその場検証する **第 3 の道 = オラクル
attestation 方式**がネイティブに書ける(第 3.5 章)。この方式は共有 UTXO を一切
参照しないため**並行性ボトルネックが構造的に存在しない**。代償は発行体が全転送を
実質ゲートする(=常時オンライン必須・検閲点・単一障害点、パターン C = Liquid AMP 型
co-signer と同型のトラストモデル)ことだが、規制ステーブルコイン(USDT/USDC の
「発行体が全権を持つ」思想)にとっては、この代償はむしろ freeze/pause を即座かつ
完璧に効かせられるという長所に転じる。ただし `OpCheckSigFromStack` opcode 自体は
KOB では未使用である。KOB の price attestation 配線(sigScript でデータを運び
covenant が読む、`spot/order.rs:95-113`)は近い配線経験だが別 opcode(生データ読み
出し)であり、この区別は第 3.5 章で正確に扱う。

**KOB への含意。** KOB が stablecoin covenant を発行するなら、既存の
`transfer`/`transfer_delegator` に加えて issuer-authority extension(seize 分岐 +
per-UTXO frozen フラグ)を実装する必要がある。さらに、KOB は covenant orderbook
DEX であるため、**issuer-freeze/seize 付き資産を注文エスクローの担保に取ると、
エスクロー中に発行体が没収した瞬間に settle 不能となり注文が沈黙死するリスク**
(`KCC20_ISSUES.md §5.6`、ISSUE-15 と同型)がある。この座礁リスクは、凍結可能性を
descriptor から機械判読可能にすることで事前回避すべきである。



## 2. 機能マスターリスト × KCC 照合表

各行は調査B の全機能。列は次の 4 つ:

- **規制優先度**: MUST(規制上ほぼ必須)/ SHOULD(推奨、片方の主要発行体のみ実装)
  / OPTIONAL(任意、汎用決済では条件付き禁止)。
- **KCC-0020 現状**: `core` = base state / transfer に含む / `ext:BR` = 唯一の定義
  済み extension(Borrowed Receive)でカバー / `なし` = core にも定義済み extension
  にも無い(=要 named extension)。
- **KOB 実装**: KOB の現行コードに実装があるか。
- **UTXO 実現パターン(調査A)**: A=インデクサ合意 / B=reissuance token / C=必須
  co-signer / D=registry cell + covenant introspection / E=発行体不在アルゴリズム
  / F=クライアントサイド検証 / G=Universe 非承認。

| # | 機能 | 規制優先度 | KCC-0020 現状 | KOB 実装 | UTXO 実現パターン |
|---|------|:---:|------|------|------|
| 1 | **mint(発行)** | MUST | なし(`transfer` は amount 保存のみ、発行エントリポイント無し) | なし | B(reissuance token / group key)または D |
| 2 | **burn(償却)** | MUST | なし(償却エントリポイント無し) | なし | B / ネイティブ(unspendable へ送る) |
| 3 | **supply-cap / 供給整合性** | MUST | 部分: `transfer` は total 保存を意図するが cardinality 上限が仕様に無く、unroll 境界外の input が保存則を逃れて**インフレ可能**(ISSUE-19) | あり(緩和): `KCC20_TRANSFER_MAX_N=4` + `OpCovInputCount/OpCovOutputCount` の `OP_VERIFY` 2 本で境界超過を reject(`transfer.rs:130`, `:336-350`) | transfer covenant 内在。グローバル発行上限は D |
| 4 | **freeze / blacklist** | MUST | なし(grep 0 件、`KCC20_ISSUES.md §5.1`) | なし(`kcc20_issuer_authority_v1` を §5.5 で提案済み、未実装) | **D**(registry cell + introspection)が唯一の UTXO ネイティブ解 |
| 5 | **seize / 没収** | MUST | なし | なし(`issuer_seize` 分岐を提案) | **D**(owner 署名なしの強制第三者転送) |
| 6 | **pause(全体停止)** | SHOULD(USDC 実装 / USDT 無し=必須でない) | なし | なし | D(グローバル halt フラグ cell) |
| 7 | **redemption(償還権)** | MUST | なし(本質的にオフチェーン + burn-to-redeem) | なし | オフチェーン + burn(B) |
| 8 | **role-separation(ロール分離)** | MUST | なし(descriptor に authority フィールド無し) | なし | 複数 issuer 鍵 / covenant-id に分離(D) |
| 9 | **reserve-attestation(準備金照会)** | MUST | なし(本質的にオフチェーン監査) | なし | オフチェーン oracle / optional attestation cell |
| 10 | **metadata(name/symbol)** | SHOULD(実務必須) | なし(descriptor は template 同定用、name/symbol 無し) | あり(`token.rs` の ad hoc `TokenDescriptor`) | オフチェーン descriptor |
| 11 | **decimals(小数桁)** | SHOULD(実務必須) | なし(`amount` は integer、decimals フィールド無し) | なし | descriptor / extended_state |
| 12 | **KYC / travel-rule** | SHOULD(規制、主にランプ側) | なし | なし | オフチェーン(on/off ramp)、G |
| 13 | **upgradeability(アップグレード)** | SHOULD | なし(template hash 不変が kcc-0001 §7 の設計、意図的に難しい) | なし | 別 template への migration(kcc-0001 §8.5 different-template continuation) |
| 14 | **rescue(誤送金回収)** | SHOULD(USDC は rescuer ロール) | なし | なし | seize の部分集合 → D |
| 15 | **allowlist(許可制)** | OPTIONAL(汎用決済では条件付き禁止 = blacklist 型を採る) | なし | なし | C(co-signer)/ D(registry) |

**読み方。**

- **MUST=8 件(#1,2,3,4,5,7,8,9)がすべて KCC-0020 に未標準化。** ただし #7
  redemption と #9 reserve-attestation はオフチェーン / 法的レイヤが主で、オンチ
  ェーンには「burn フック」「attestation 参照」程度で足りる。純オンチェーン
  covenant 拡張を要する MUST は **#1 mint / #2 burn / #3 supply 整合 / #4 freeze /
  #5 seize / #8 role-separation の 6 件**。
- **UTXO ネイティブに freeze/seize/pause を実現できるのはパターン D のみ**だが、
  CIP-113(Cardano、preview/testnet)も RCE(Nervos、RFC は明確だが mainnet 採用
  事例なし)も**本番未実証**である。したがって「D で書けるはず」は設計レベルの見
  通しであり、実運用実績の裏付けは現時点で存在しない。
- KOB が既に持つのは #3 の緩和(cardinality 境界 reject)と #10 の ad hoc metadata
  のみで、発行体コントロール(#4/#5/#6)は一切実装していない(提案段階)。
- **base `State` / `transfer` を変更せずに済む**のが重要点。#1〜#9 はすべて
  descriptor の `kcc20_extensions` 経由の named extension、または extended_state /
  別エントリポイントで表現でき、Manyfest の minimal core を汚さない。



## 3. 各 gap の深掘り(freeze / seize / supply-cap)

### 3.1 なぜ KCC の minimal core にこれらが無いか(Manyfest の設計思想)

KCC-0020 は「トークン covenant が認識・転送・合成されるために必要な covenant
surface」だけを定義すると冒頭で宣言し(`kcc-0020.md` L12-13)、state・transfer
interface・descriptor の 3 点に絞っている。mint / burn / freeze / seize / supply
cap はすべて core の外に置かれ、拡張は `kcc20_extensions: ExtensionId[]`(descriptor
の optional フィールド)経由の named extension として宣言する設計になっている。
定義済み extension は Borrowed Receive v1 のみ(`kcc-0020.md` L137-138)。

これは欠落ではなく、著者 Manyfest の意図的な minimal-core 主義である。狙いは
2 つと読める:

1. **core を汚さず合成性を守る。** base state を 4 フィールド固定にし、transfer
   を「amount 保存 + 認可 + successor 検証」だけに限定することで、任意のトークン
   covenant が同じ transfer interface で相互運用でき、wallet / DEX / facilitator
   が共通ロジックで扱える。issuer 固有のポリシーを core に入れると、この最小共通
   面が崩れる。
2. **issuer policy は token 固有で多様。** freeze の粒度(アドレス単位か UTXO 単位
   か)、seize の宛先規則、ロール分離の構造は発行体ごとに異なる。Manyfest 自身が
   スレッド #8 post #9 で「there is no global token state ... it's tricky to allow
   global lists, freezes and such」と述べ、これを core ではなく「global state utxo
   を強制する token」という**特定 token の設計**として位置づけている
   (`KCC20_ISSUES.md §5.3`)。

したがって「KCC-0020 に freeze が無い」は仕様バグではなく scope の線引きである。
正しい問いは「core に足すべきか」ではなく「**どの拡張カテゴリとして標準化すれば、
minimal core を保ったままステーブルコインの実務要件を満たせるか**」である。

### 3.2 UTXO で実装する場合 — パターン D を Kaspa の introspection でどう書くか

調査A の結論は、UTXO の自己主権を保ったまま freeze を実現できるのは**パターン D
(オンチェーン registry cell + covenant introspection)のみ**であり、他は次のいず
れかに退化する:

- A(インデクサ合意 / Omni)= UTXO 性を放棄しアカウント帳簿化。Kaspa KRC-20 と同型。
- B(reissuance token)= 追加発行制御のみ、既発行分の freeze/seize は**不可能**。
- C(必須 co-signer / Liquid AMP)= 全転送に issuer 署名必須 = 実質 freeze だが
  permissionless 性を放棄した準中央集権。
- E/F/G = freeze の強制力がそもそも無い(E は発行体不在、F はウォレットが拒否リス
  トを無視可能、G は base layer 強制力なしの「否認」に留まる)。

Kaspa には**パターン D を組む材料が既に揃っている**。KOB は covenant introspection
opcode 群を既に自実装・engine テスト済みで、`kob/core/src/contract/opcodes.rs` に
以下が実装されている:

- **covenant-id メンバーシップ系(KIP-20 Covenant IDs §5 由来)**:
  `OP_INPUTCOVENANTID`(0xcf, opcodes.rs:108)、`OP_COVINPUTCOUNT`(0xd0, :109)、
  `OP_COVINPUTIDX`(0xd1, :110)、`OP_COVOUTCOUNT`(0xd2, :111)。KIP-20 §5.4 は
  出力側の `OpOutputCovenantId`(0xd5)も定義する。
- **トランザクション introspection 系(KIP-10 由来、mainnet 有効化)**:
  `OP_TXINPUTAMOUNT`(0xbe)、`OP_TXINPUTSPK`(0xbf)、`OP_TXOUTPUTAMOUNT`(0xc2)、
  `OP_TXOUTPUTSPK`(0xc3)、`OP_SUBTRACTOUTPUTS`(0xc7)。

> 注: 本レポートでは、covenant-id メンバーシップ opcode を KIP-20、amount/SPK の
> tx introspection opcode を KIP-10 と表記する。両者は KOB の `opcodes.rs` に実装
> され、mainnet(KIP-10 / Toccata)で有効化済みである。パターン D は**両方**を必
> 要とする — レジストリ / authority cell を covenant-id で同定し、その cell の値と
> 各出力の SPK / amount を tx introspection で検証する。

KOB の introspection 実装経験を根拠に、パターン D を Kaspa 上で組む場合の**設計
レベルの見通し**(具体バイトレイアウトは示さない)は次の通り:

**(i) freeze — per-UTXO フラグ方式(推奨、並行性に優しい)。**
凍結状態を「グローバル BL 表」ではなく、**各トークン UTXO 自身の `extended_state`
に `frozen: bool` 相当のフィールドとして持たせる**。transfer 分岐は自分自身の state
の `frozen` を読むだけで完結し、グローバル state を毎回参照しない。凍結は発行体が
その UTXO を `frozen=true` の successor に強制遷移させる別分岐で行う。base transfer
は既に `extended_state_digest` を opaque に保存する規約(`kcc-0020.md` L71-73)を
持つので、拡張 state 内に凍結ビットを載せること自体は core と衝突しない。

**(ii) seize — owner 署名なしの強制第三者転送。**
通常の transfer は `owner_identifier` を `OpCheckSigVerify` の pubkey に据えて所有者
署名を要求する(KOB の `TOKEN_UNIT_BODY` / `transfer_delegator` が既に採る標準パ
ターン、`transfer.rs` module doc L70-77)。seize はこの分岐とは**別のエントリポイ
ント** `issuer_seize` を設け、そこでは所有者署名の代わりに**発行体署名 1 つ**を検証
し、successor の `owner_identifier` を発行体指定の宛先に書き換えることを許す。発行
体鍵は descriptor に固定 identifier(`identifier_type` と同型の 32byte)として公開
しておく。covenant-id introspection で「この seize が正しい token 系列に属する」こ
とを保証する。

**(iii) supply-cap / インフレ防止。**
供給整合性は 2 層に分かれる:
- **転送レベルの保存則**は既に KOB が緩和実装している。Kaspa Script はループを持
  たないため N-of-N の amount 保存検証は必ず固定境界に unroll せざるを得ず、境界外
  の input が保存則を逃れると**存在しないはずの amount が successor に現れる(イン
  フレ)**。KOB は `KCC20_TRANSFER_MAX_N=4`(`transfer.rs:130`)を置き、
  `OpCovInputCount ≤ MAX_N+1` / `OpCovOutputCount ≤ MAX_N` を `OP_VERIFY` で強制
  して境界超過 transition を**全体 reject** する(`transfer.rs:336-350`)。これは
  KCC-0020 が要求していない KOB 独自の防御であり(ISSUE-19、HIGH)、仕様側に
  「MUST reject overflow」条項と descriptor の `max_participants` 公開を提案済み。
- **発行レベルの上限(mint 権限)**は別問題で、これはグローバル state(発行済み総量)
  を参照する必要があり、(i)/(ii) より本質的に並行性ボトルネックを招きやすい。準備
  金 1:1 を厳格にオンチェーン強制するには供給カウンタ cell が要り、これは 3.3 の
  問題に直撃する。実務上は mint を発行体の集中操作(低頻度・直列で構わない)に限定
  し、高頻度の transfer をグローバル state から切り離すのが現実的である。

### 3.3 並行性ボトルネック — Kaspa BlockDAG にとって最も痛い緊張点

アカウントモデル(EVM の ERC-20 blacklist)なら「アドレス → フラグ」を 1 つの
ストレージスロットに持てるが、UTXO でこれを素朴に模倣する(= 1 個のグローバル
BL 表 UTXO を毎 transfer で参照・更新する)と、**その cell が全 transfer の直列化点
になり、同時並行 transfer が不可能になる**(`KCC20_ISSUES.md §5.4`)。これは Kaspa
の BlockDAG による高並列性という設計目標と真っ向から矛盾する。Manyfest 自身の
「global state utxo を強制する token」案(§5.3)も、この意味で同じボトルネックを
抱えている。パターン D の唯一性(UTXO ネイティブ freeze の唯一解)と、その並行性
コスト(グローバル cell が直列化点)は表裏一体であり、これが本テーマ最大の緊張点
である。

**緩和の方向性(既存議論との対応)。**

- **per-UTXO frozen フラグ + 独立 seize 分岐(本レポート推奨)**: 3.2(i)/(ii) の
  設計。通常 transfer はグローバル state に触れず自分の state だけで完結するため、
  無関係な transfer 同士の並行性を壊さない。発行体操作(freeze 適用 / seize)のみ
  がグローバルまたは per-UTXO の書き換えを伴うが、これらは低頻度でよい。これは
  Max143672 の "additional spending branch"(スレッド #8 post #20)を具体化した
  ものである(`KCC20_ISSUES.md §5.3`)。
- **two-phase transfer(pending / ready-to-spend)**: Max143672 post #21 の案。
  send は宛先へ渡すだけ、spend 時にグローバル state を参照させることで、通常送金
  の並行性を保ちつつ最終確定時のみチェックする。KOB 提案では、`issuer_seize` の
  対象 UTXO がちょうど transfer 実行中で競合するケースの将来拡張方向として位置づけ
  る(`KCC20_ISSUES.md §5.5` 末尾)。

いずれも狙いは同じ — **「凍結の可否判定」を通常経路の直列化点にしない**こと。
グローバル state を持つ設計を選ぶ場合でも、それを参照するのは発行体分岐と一部の
確定操作に限り、高頻度の平常 transfer を触れさせない構造が Kaspa では必須である。

### 3.4 決定的事実 — Kaspa には reference input が無い(コードで確認済)

3.3 の並行性問題は、Kaspa に固有のある事実によって **CIP-113 / RCE をそのまま移植
できないレベルまで深刻化する**。それは「**Kaspa の Transaction は inputs / outputs
しか持たず、consume せず read-only で UTXO を参照する reference input(Cardano
CIP-31 相当)が存在しない**」という事実である。裏取り:

- `consensus/core/src/tx.rs:254-269` の `Transaction` 構造体は `inputs:
  Vec<TransactionInput>` と `outputs: Vec<TransactionOutput>` のみで、reference /
  read-only input のフィールドを持たない。
- covenant introspection opcode は**すべて「このトランザクションの input」しか読め
  ない**。`OpInputCovenantId`(0xcf, `crypto/txscript/src/opcodes/mod.rs:1500`)は
  対象が input でなければ `"OpInputCovenantId only applies to transaction inputs"`
  を返して失敗する(同 :1510)。`OpTxInputSpkLen` / `OpTxInputSpkSubstr` も同様に
  `"only applies to transaction inputs"` で拒否する(:1362, :1379)。KOB がこの
  introspection を自実装・engine テストしている経験そのものが根拠であり、**ある
  UTXO を introspection で読むには、その UTXO を input に含める = spend することが
  必須**である。

**含意 1 — CIP-113 をそのまま Kaspa に移植するとボトルネックが CIP-113 以上に深刻。**
Cardano CIP-113 と Nervos RCE が「共有 denylist UTXO / cell を spend せずに全転送
から同時参照できる」のは、まさに **reference input / cell 参照という read-only 参照
機構があるから**である。複数の並行転送が同一の denylist を同時に read-only 参照でき、
denylist UTXO は消費されないので二重支出の競合が起きない。**Kaspa はこれができない。**
共有 denylist UTXO を introspection で参照するには spend が必要で、その瞬間その UTXO
は消費される。したがって全転送が同じ 1 個の denylist UTXO を二重支出で奪い合う形に
なり、**1 ブロックあたり実質 1 転送に縮退する**。つまり「CIP-113 の設計を Kaspa に
そのまま持ってくる」は、reference input 非対応ゆえに CIP-113 本体よりもボトルネック
が深刻になる。3.3 で述べたグローバル state cell の直列化問題は、Kaspa では
「更新の直列化」ではなく「参照そのものの直列化(read even to read = spend)」という
より厳しい形で顕在化する。

**含意 2 — Kaspa 固有の現実解 = denylist root を各コインに焼き込む。**
共有 UTXO を消す方向に設計を倒す。denylist を SMT(Sparse Merkle Tree)化し、その
**root hash を各コインの covenant state(`extended_state`)に焼き込む**。転送時、
送り手が受取人の **non-membership proof を sigScript で渡し**、covenant がそれを自分
の state に載っている root に対して検証する。この方式なら denylist の参照が各コイン
UTXO に分散し、共有参照 UTXO が消滅するため**並行性ボトルネックがゼロ**になる
(各転送は自分の 2 つの UTXO しか触らない)。代償は**反映ラグ**である: 発行体が
blacklist を更新すると root が変わるが、既に流通しているコインの state に焼かれた
root は古いままで、**各コインが次に動く時、または定期 rotation の時にしか新しい root
を取り込めない**。すなわち「凍結の即時グローバル反映」と「並行性」はトレードオフの
関係にあり、Kaspa では後者を取るなら前者に反映ラグが伴う。これは CIP-113 の
withdraw-zero / O(1) 不在証明が「共有参照は可能・更新コストを下げる」方向の緩和で
あるのに対し、Kaspa では「共有参照そのものを消す」方向に緩和せざるを得ない、という
質的な違いである。

**含意 3 — mint と transfer で参照方式を変える設計判断が要る(非対称性)。**
すべての操作が同じ制約を受けるわけではない。**mint は低頻度で発行体単独**の操作
なので、共有 UTXO(供給カウンタ / authority cell)を spend-参照しても、同時に走る
別の mint がほぼ無いため競合しない — 直列でよい。一方 **transfer は高頻度で多数が
同時**に走るため、共有参照(= spend 競合)にすると 3.4 含意 1 の縮退を起こす。
したがって「発行時は共有 state を参照、転送時は各コインに焼いた root を参照」と、
**操作の頻度に応じて参照方式を切り替える**のが Kaspa での正しい設計判断になる。
3.2(iii) で触れた「mint はグローバル state 参照でよいが transfer は切り離す」は、
この非対称性の具体化である。

**含意 4 — seize は並行性問題とは独立した別レイヤ。フレームの統一。**
流通済みコインの **seize(没収)は denylist 参照とは別の話**であり、並行性問題とは
独立に解ける。各コインの covenant に最初から「**発行体署名 1 つで強制移転できる経路**」
(3.2(ii) の `issuer_seize` 分岐)を埋め込んでおけばよい。これは共有 state を参照
しないので並行性を一切損なわない。seize は発行体の中央集権的権限そのものであり、
ステーブルコインでは当然に入れてよい機能である。

ここで本テーマのフレームを統一しておく。争点は「**中央集権 vs 分散**」ではない —
規制ステーブルコインは定義上、発行体が freeze / seize / mint 権限を持つ中央集権的
資産である。真の争点は「**その中央集権的権限を、UTXO / BlockDAG 上で並列性を殺さず
に執行する方式**」である。seize(含意 4)は権限を各コインに埋め込むことで並列性と
無関係に解決され、freeze の即時性(含意 2)だけが並列性とのトレードオフに直面する。
KOB / KCC の設計課題は「発行体権限を無くすこと」ではなく「**発行体権限を持ちつつ、
高頻度 transfer の並列性を守る参照方式を選ぶこと**」に尽きる。

### 3.5 freeze 執行の3方式比較 — オラクル attestation という第3の道

3.3/3.4 で見た並行性問題を踏まえ、Kaspa 上で freeze を執行する現実的な選択肢を
3 つに整理する。(1)(2)は 3.4 で個別に検討済みの内容の再整理であり、(3)は本節で
新たに追加する経路である。

**(1) 共有 denylist UTXO を introspection 参照(却下)。**
3.4 含意 1 の通り、Kaspa には reference input が無いため、共有 denylist UTXO を
introspection で参照するには spend が必須になる。したがって全転送が同一 UTXO を
二重支出で奪い合い、**1 ブロックあたり実質 1 転送に縮退する**。CIP-113 / RCE を
そのまま移植する経路であり、Kaspa では採用できない。

**(2) SMT root 焼き込み + non-membership proof(3.3/3.4 で既述の Kaspa 固有解)。**
denylist を SMT 化し、その root を各コインの `extended_state` に焼き込む。発行体は
root 更新のみを行えばよく(低頻度・オフライン可)、転送側は sigScript に載せた
non-membership proof で covenant に対し自己証明する。共有参照 UTXO が消えるため
permissionless 性寄り・並行性ボトルネックはゼロだが、**凍結の反映に各コインが次に
動くまでのラグが伴い、即時 freeze には向かない**。

**(3) オラクル attestation — `OpCheckSigFromStack` によるゲート(新規に追加する経路)。**
発行体(オラクル)が「この受取人は clean」「この転送を許可する」という 32byte
メッセージハッシュに署名し、転送者がその署名を sigScript に載せる。転送 covenant は
`OpCheckSigFromStack`(0xd7、`crypto/txscript/src/opcodes/mod.rs:1634`。ECDSA 版
`OpCheckSigFromStackECDSA` 0xd8 は `:1645`)でその場、トランザクション自身の
sighash とは独立にこの署名を検証する。blacklist の判定ロジックそのものはチェーン外
(発行体サーバー)に留まり、**オンチェーンには一切露出しない**。共有 UTXO を一切
参照しないため、**並行性ボトルネックが構造的に存在しない**(各転送は自分の入出力と
発行体署名だけで完結する)。代償は、発行体が実質すべての転送をゲートする=**常時
オンライン必須・単一検閲点・単一障害点(SPOF)** であることで、これはパターン C
(Liquid AMP 型必須 co-signer)と同型のトラストモデルに帰着する。ただし規制ステーブ
ルコインでは「発行体が全転送をゲートし freeze/pause を即座かつ完璧に効かせられる」
ことはむしろ求められている機能であり、USDT/USDC のような「発行体が全権を持つ」思想
とは整合的である(欠陥ではない)。

> **KOB との関係(正確な区別)。** KOB は price attestation(`spot/order.rs` の
> CANONICAL PRICE ATTESTATION、95-113 行付近)で「sigScript にデータを載せ covenant
> が読む」配線を既に実装・engine テスト済みだが、これは `OpTxInputScriptSigSubstr`
> (0xbc、`transfer.rs` 等ではなく `spot/order.rs` の `TXINPUTSIGSUBSTR` 定数)による
> **生データの読み出し**であり、署名検証ではない。`OpCheckSigFromStack` 自体は KOB の
> どのエントリポイントでも使われていない。それどころか、KOB は `transfer_delegator()`
> の認可方式を検討した際にこの opcode を「leader が全 consumed state 分の署名を
> `OpCheckSigFromStack` で検証する」案(a)として一度俎上に載せ、「kcc-0001 に一切
> 登場せず、メッセージハッシュ規約も未定義」を理由に**明示的に不採用とし**、(b)
> delegator 自己認可(標準の `OpCheckSigVerify` パターン)を採用した経緯がある
> (`kcc20/transfer.rs:62-67`、`KCC20_ISSUES.md` ISSUE-12)。したがって本節の (3)
> オラクル attestation は、KOB にとって「配線経験の延長」ではなく、**過去に別目的で
> 検討・不採用にした opcode を、全く別の用途(発行体 freeze ゲート)で新規に採用する
> 提案**である。誇張を避けるためこの区別を明記する。

**3方式比較表。**

| 方式 | 執行主体 | 発行体オンライン要否 | 即時 freeze 可否 | 並行性 | blacklist のチェーン露出 | トラストモデル |
|---|---|---|---|---|---|---|
| (1) 共有 denylist UTXO introspection 参照 | covenant(共有 UTXO 読み=spend 必須) | 不要(表更新は低頻度) | 可(参照時点の表を見る) | **1 ブロック 1 転送に縮退(却下)** | オンチェーン全公開 | permissionless 寄り、ただし不採用 |
| (2) SMT root 焼き込み + non-membership proof | covenant(各コイン local proof 検証) | 不要(root 更新のみ、低頻度・オフライン可) | 不可(反映ラグ、次にコインが動くまで旧 root) | 高い(共有 UTXO ゼロ) | root(コミットメント)のみオンチェーン、表自体は非公開 | permissionless 寄り |
| (3) オラクル attestation(`OpCheckSigFromStack`) | covenant + 発行体署名(全転送ごと) | **必須(常時オンライン、全転送に署名)** | 可(即時、署名時点の最新判定) | 高い(共有 UTXO ゼロ、各 tx local に検証) | 非公開(判定ロジックそのものがチェーン外) | パターン C(Liquid AMP co-signer)と同型、実質準中央集権 |

いずれも「発行体権限を無くす」方式ではなく、3.4 末尾で統一したフレームの通り
「**中央集権的権限を UTXO 上で並行性を殺さず執行する方式**」の選択である。(2)は
permissionless 性を優先し反映ラグを許容する設計、(3)は即時性とオンチェーン非露出を
優先し発行体オンライン常駐を許容する設計であり、両者はトレードオフの両端に位置する。
規制ステーブルコインの実務(発行体が freeze/pause を即座に効かせる義務を負う)には
(3)が最も自然に適合する。

### 3.6 CIP-113 / RCE の先行例との対応(いずれも本番未実証)

パターン D の 2 つの先行例は、Kaspa で組む際の参照設計になるが、**どちらも mainnet
本番実証が無い**点を明記する:

- **Cardano CIP-113(programmable tokens / denylist)**: 転送 validator がソート済み
  linked list の denylist を参照し、O(1) メンバーシップ(不在)証明を要求する。
  withdraw-zero パターンで並行コストを下げる工夫がある。ただし **testnet / preview
  段階で監査未了**であり、本番採用実績は無い。
- **Nervos CKB xUDT + RCE(Regulation Compliance Extension)**: SMT(Sparse Merkle
  Tree)ツリー + AdminList で Whitelist / Blacklist / Emergency Halt / PKI の 4 機能
  を RFC として明示している。設計は明確だが **mainnet 採用事例が無い**。

Kaspa へのマッピングは 1:1 ではない。CIP-113 の「validator が共有 denylist を参照」
も RCE の「SMT メンバーシップ + AdminList」も、**reference input / cell 参照という
read-only 参照機構に依存している**が、3.4 で確認した通り **Kaspa にはこれが無い**。
したがって「共有 denylist を全転送が同時参照する」CIP-113 型の構造をそのまま持ち込む
と、3.4 含意 1 の通り 1 ブロック 1 転送に縮退する。Kaspa では代わりに、denylist の
SMT root を各コインの `extended_state` に焼き込み、送り手が non-membership proof を
sigScript で渡す方式(3.4 含意 2)で、共有参照そのものを消す方向に置き換えるしかない
— 代償は凍結更新の反映ラグである。KIP-20 の covenant-id / KIP-10 の tx introspection
は、この各コインローカルな proof 検証の材料としては使えるが、CIP-113 のような共有
UTXO の並行 read-only 参照には使えない。**繰り返すが、D パターンは先行 2 例とも未実証
であり、「Kaspa で D を組めば freeze が実運用できる」は設計上の見通しであって実証さ
れた事実ではない。** 調査A の総括の通り、UTXO の自己主権を保ったまま freeze を実運用
した例は事実上ゼロである。



## 4. KCC への提案

`KCC20_ISSUES.md §5.5` で提出済みの `kcc20_issuer_authority_v1` 提案を土台に、
ステーブルコイン全機能をカバーする形へ拡張する。原則は一貫して「**base `State` /
`transfer` を一切変更せず、descriptor の `kcc20_extensions` 機構だけを使って named
extension category として標準化する**」ことである。

### 4.1 core に足すべきでないもの(Manyfest 尊重)

以下は core に入れるべきではない。理由は 3.1 の通り、合成性を守る最小共通面を壊す
から、かつ発行体ごとに多様だからである:

- **freeze / seize / pause / mint / burn のロジック本体**を base `transfer` に
  分岐として押し込むこと。→ 独立エントリポイントまたは extension 側に置く。
- **issuer identifier / authority フィールドを base `State` の 5 番目の必須
  フィールドにする**こと。→ 発行体を持たないトークン(#5 の E 型アルゴリズム
  ステーブルや純粋な utility token)には不要な負担。extended_state / descriptor
  側に置く。
- **利息付与(rebasing / yield)**。これは規制上明示禁止(GENIUS Act 系)であり、
  そもそも標準化対象にしない。

### 4.2 named extension category として標準化すべきもの

descriptor の `kcc20_extensions` に宣言する形で、次の 3 カテゴリを提案する。いずれ
も宣言を **descriptor に必須(MUST)** とすることで、wallet / DEX / エスクロー実装
が「この資産は発行体コントロールを受けるか」をオンチェーン実行前に静的判定できる
ようにする(= 凍結可能性の機械判読可能性、4.4 の並行性注意とも接続)。

**(A) `kcc20_issuer_authority_v1`(freeze / seize / pause / role-separation)。**
`KCC20_ISSUES.md §5.5` の提案を全機能へ一般化:
- descriptor に発行体 identifier(群)を持たせる。**ロール分離**(USDC の
  masterMinter / pauser / blacklister / rescuer / seizer に対応)は、単一の
  発行体鍵ではなく**ロールごとに別 identifier / covenant-id を宣言**することで表現
  する。これで #8 role-separation も同じ枠組みで満たせる。
- `transfer` とは別に `issuer_seize(...)`(seize / rescue #5/#14)を定義。発行体
  署名 1 つで対象 UTXO を指定宛先へ強制移動。rescue(誤送金回収)は seize の宛先を
  誤送信元にした部分集合として扱う。
- **freeze** はグローバル BL 表を必須にせず、**各コインに参照を分散させる**方式を
  推奨する。最小形は per-UTXO 凍結フラグ(3.2(i))。動的な blacklist 更新が要る場合、
  descriptor で次の **2 方式のいずれかを選択可能**にする(3.5 の3方式比較、両論併記):
  - **SMT root 方式**: denylist の SMT root を各コインの `extended_state` に焼き込み
    non-membership proof を sigScript で渡す(3.4 含意 2)。共有参照 UTXO を消して
    並行性を守る代償として凍結更新に反映ラグが伴う。permissionless 性・発行体
    オフライン可を優先する場合に選ぶ。
  - **オラクル attestation 方式**: 発行体(オラクル)が受取人 clean / 転送許可の
    署名を都度発行し、転送者が sigScript に載せ、covenant が `OpCheckSigFromStack`
    (0xd7、`crypto/txscript/src/opcodes/mod.rs:1634`)でその場検証する(3.5(3))。
    共有 UTXO を参照しないため並行性ボトルネックは同様に無く、かつ反映ラグが無い
    (即時 freeze 可能)が、発行体が全転送に署名するため常時オンライン必須・SPOF
    となる(パターン C と同型のトラストモデル)。即時性を優先する規制ステーブル
    コインに向く。
  いずれの方式でも reference input が無い Kaspa では CIP-113 型の共有 denylist 参照
  は採れない(3.4)。descriptor はどちらの方式を採るか(または併用するか)を宣言する
  MUST フィールドを持つべきである。
- **pause**(#6, SHOULD)はグローバル halt フラグ cell を参照する分岐として定義
  するが、平常 transfer には参照させない(3.3)。USDT が pause を持たない事実の通り
  必須ではないので、この extension 内の optional sub-feature とする。

**(B) `kcc20_supply_control_v1`(mint / burn / supply-cap)。**
- 発行体署名による `mint` / `burn` エントリポイントを定義(#1/#2)。準備金 1:1 は
  オフチェーン監査に委ねるが、オンチェーンでは mint を発行体ロールに限定する。
- **supply 整合性**は 2 段構え。転送レベルは ISSUE-19 の提案(Transfer Interface
  末尾に「境界超過を MUST reject」条項 + descriptor の `max_participants` 公開)を
  そのまま採用。発行レベルの総量上限が必要な場合のみグローバル供給カウンタ cell を
  導入し、これは低頻度の mint/burn 分岐だけが触れる(3.2(iii))。

**(C) `kcc20_compliance_meta_v1`(metadata / decimals / KYC / reserve-attestation
参照)。**
- **decimals**(#11)と **metadata**(name / symbol、#10)を descriptor の宣言的
  フィールドとして標準化。`amount` は integer のままとし、decimals は表示レイヤの
  スケール宣言として持つ(オンチェーン算術は integer 保存則を崩さない)。
- **reserve-attestation**(#9)と **KYC / travel-rule**(#12)は本質的にオフチェーン
  なので、covenant で実装するのではなく、descriptor に「attestation URL / oracle
  covenant-id」「compliance policy 識別子」を宣言するフックだけを標準化する。
- **redemption**(#7)も同様に、burn-to-redeem の burn エントリポイント(B)への
  参照 + オフチェーン償還窓口の宣言に留める。

### 4.3 KCC20_ISSUES.md の既存提案との整合

本提案は `KCC20_ISSUES.md` の既存の指摘と矛盾せず、これを拡張する:

- **§5.5 `kcc20_issuer_authority_v1`** → 上記 (A) がその全機能一般化。Max143672 の
  "additional spending branch"(独立 `issuer_seize`)を採り、two-phase transfer を
  将来拡張の競合解決策として残す点も踏襲。
- **ISSUE-19(cardinality / supply インフレ)** → (B) の supply 整合性層がそのまま
  対応。`max_participants` を descriptor 必須フィールドにする提案を再掲。
- **ISSUE-6 / ISSUE-7(descriptor のワイヤ形式・`ExtensionId` エンコード未定義)**
  → 本提案の 3 extension を実際にオンチェーンで宣言・発見させるには、**先に
  descriptor のワイヤ形式と `ExtensionId` エンコードを確定させることが前提**になる。
  ステーブルコイン拡張は、descriptor 標準化(ISSUE-6/7)を「あれば良い」から「実務
  ブロッカー」に格上げする具体ユースケースである(x402 facilitator が外部発行
  トークンの template を発見できない問題、§4.2 と同型)。
- **ISSUE-4 / ISSUE-18(`identifier_type = SCRIPT_HASH / COVENANT_ID` の所有権検証
  未定義、実装は PUBKEY のみ)** → seize の宛先や発行体 identifier に covenant-id を
  使う場合、この所有権検証規則の確定が前提になる。

### 4.4 Kaspa 固有の並行性問題への設計上の注意

extension を標準化する際、Kaspa の BlockDAG 並列性を壊さないために次を**規範**と
して盛り込むことを提案する:

1. **平常 transfer をグローバル state 参照から切り離す。** freeze 判定は各コイン
   ローカル(自 state 読み / 焼き込んだ denylist root への proof 検証)で完結させ、
   グローバル cell 参照は発行体分岐 / 低頻度確定操作に限定する。Kaspa には reference
   input が無く、共有 UTXO の参照は spend(消費)を要するため(3.4)、**グローバル
   BL 表 UTXO を毎 transfer で参照させる設計は 1 ブロック 1 転送への縮退を招く
   アンチパターン**として明記する。mint(低頻度・単独)と transfer(高頻度・並行)で
   参照方式を変える非対称設計を許容する。オラクル attestation 方式(3.5(3))もこの
   原則に適合する — 検証対象は発行体の署名であって共有 UTXO ではないため、平常
   transfer は依然としてグローバル cell に触れず、並行性ボトルネックを回避する。
2. **新しい遷移 shape を descriptor から機械判読可能にする。** `issuer_seize` の
   ような、通常 `transfer` / `transfer_delegator` と異なる shape の covenant 遷移が
   同一 covenant-id 系列に混在すると、他実装(DEX 等)の「一様 shape 前提」の読みを
   静かに壊す(ISSUE-15 と同型、`KCC20_ISSUES.md §5.6`)。拡張が定義する各遷移
   shape を descriptor に記述させることを MUST にする。
3. **凍結可能性の宣言を必須化する。** descriptor から「この資産は発行体 freeze /
   seize を受けうるか」が静的に判定できることを、wallet / DEX / エスクローの安全性
   要件として位置づける(4.2 冒頭 + 第 5 章)。

### 4.5 2 層アーキテクチャ — 個別経路と attestation ゲートへの統一

本章の提案を実装形態で束ねると、規制ステーブルコインの MUST 機能は **2 層**に
分解でき、いずれも covenant ネイティブに収まる。KCC-0020 の minimal core は一切
変えず、descriptor で宣言される extension として上載せできる。

**層 I — 個別コインで完結する経路(各コイン covenant 内在、並行性問題なし)**

- **mint / burn**: 発行体署名で新規 token UTXO を生成 / 消費する。**KOB は実装済み**
  (`token.rs` の `token_mint` = self-continuation + 発行体 `OpCheckSigVerify`、
  `token_burn`)。
- **seize(没収)**: 各コイン covenant に「issuer 署名 1 つで owner 同意なく強制
  移転する経路」を最初から埋める(§4.2-A の `issuer_seize`、提案・未実装)。対象
  コインを個別に処理するだけなのでグローバル state を要さず、並行性と無関係。
- **role-separation**: 経路ごとに検証鍵を別 pubkey にする / `OpCheckMultiSig`
  (0xae、実在)で multisig 化する。

層 I はいずれも「その tx が触るコインの中で完結」するため、Kaspa の BlockDAG
並列性を一切損なわない。

**層 II — グローバル状態が要る制御(オラクル attestation ゲート 1 本に集約)**

freeze / pause / supply-cap / KYC は本来グローバル state を要するが、§3.5(3) の
オラクル attestation(`OpCheckSigFromStack` 0xd7、提案・KOB 未使用)を採ると、
これらを**発行体が attestation を出す off-chain ロジックに集約**し、covenant 側は
「発行体署名が付いているか」の検証 1 本に統一できる。

- **pause は無料で付いてくる**: 発行体が attestation を出すのをやめれば全転送が
  止まる = pause。§3.5(3) の直接の帰結で、専用の halt フラグ cell(§2 表の
  pause 行「D」)を別途持たずに実現できる。
- **supply-cap は mint counter の非対称性で解ける**: mint は低頻度・発行体単独
  なので、累積発行量を持つ counter UTXO を発行体が継続 spend しても競合しない
  (§3.4 の mint / transfer 非対称性 — transfer と違い共有 UTXO 参照がボトル
  ネックにならない)。

**統合結論**: attestation ゲートを採ると freeze / pause / supply / KYC が発行体の
off-chain ロジックに一元化され、covenant は `OpCheckSigFromStack` 署名検証 1 本に
なる。これは USDT / USDC の「発行体が全権」という中央集権モデルを、UTXO covenant
に最も素直に写像したものである(トラストモデルは §3.5(3) の通りパターン C =
Liquid AMP 相当 = 発行体常時オンライン・SPOF)。**層 I(個別経路)と層 II(統一
ゲート)の 2 層で、規制ステーブルコインの MUST 機能はほぼ全て covenant ネイティブ
に実装可能**である。



## 5. KOB にとっての含意

### 5.1 KOB が stablecoin covenant を発行する場合に実装すべきもの

KOB は既に KCC-0020 準拠の surface(state / dispatch / p2sh / descriptor /
identifier)と `transfer` / `transfer_delegator` body(`kcc20/transfer.rs`、engine
テスト済み)、および covenant introspection opcode 群(`opcodes.rs`)を持つ。ステー
ブルコインを出すには、この上に第 4 章の 3 extension のうち少なくとも次を実装する
必要がある:

- **issuer-authority extension**(§4.2-A の実装): 新エントリポイント
  `issuer_seize`(発行体署名 1 つで強制第三者転送)+ `extended_state` の per-UTXO
  `frozen` フラグ。現状 `Kcc20State` は `owner_identifier` / `identifier_type` /
  `amount` / `extended_state_digest` の 4 フィールド(`state.rs`、`ENCODED_LEN=77`)
  で、`extended_state_digest` に凍結ビットを含む拡張 state をコミットする余地は
  既にある(base transfer は digest を opaque 保存)。ただし現行の
  `borrowed_receive.rs` が「stub、未実装」(module doc L2)である通り、新エントリ
  ポイントの追加は `transfer.rs` の core ループの再設計を伴い、add-on では済まない
  点に注意(同 module doc の time-box 判断)。
- **supply-control extension**(§4.2-B): 発行体 `mint` / `burn`。KOB は既に転送
  レベルのインフレ防止(`KCC20_TRANSFER_MAX_N=4` + `OpCov*Count` の `OP_VERIFY`、
  `transfer.rs:130`, `:336-350`)を持つので、発行レベルの mint 権限ゲートを足す
  形になる。
- **amount マッピングの再検討**: KOB の現行 `token_unit`(`token.rs`)は `amount` を
  UTXO の native sompi 値にマップし(`token.rs` L16-40 の設計判断: アドレス発見の
  安定性のため)、script バイトに埋めていない。一方 `kcc20/` の新実装は `amount` を
  in-script の 4 番目のフィールドとして持つ(2 つの読みが併存、`mod.rs` L25-33)。
  ステーブルコインの発行体 seize / supply 集計では、どちらの amount 表現を正本と
  するかを確定させる必要がある(covenant-id ベースの UTXO スキャンに寄せるなら
  in-script 方式、既存 DEX の address 発見を保つなら native-value 方式)。

### 5.2 DEX(spot covenant)が issuer-freeze 付き資産を担保に取る場合の座礁リスク

KOB は covenant orderbook DEX(spot covenant が注文資産をエスクロー)であり、ここ
に **issuer-seize 権限付き資産を担保として載せると固有のリスク**が生じる
(`KCC20_ISSUES.md §5.6` で既出):

- **エスクロー座礁 / 沈黙死**: issuer-seize 権限を持つ資産が KOB 注文 covenant の
  エスクロー中に発行体に没収されると、settle 処理は「エスクローされているはずの
  資産が消えている」状態に直面し、**settle 不能のまま注文が沈黙死する**(エラーで
  気づかれずに放置される)。DEX がロックしたつもりの担保が、DEX の合意なしに第三者
  (発行体)によって引き抜かれる、という UTXO covenant DEX 固有の穴である。
- **ISSUE-15 との連鎖**: `issuer_seize` は通常の `transfer` / `transfer_delegator`
  とは異なる shape の covenant 遷移を同一 covenant-id 系列に持ち込む。KOB の leader
  が sibling(delegator)の consumed state を固定オフセットで読む設計(ISSUE-15、
  HIGH)は「一様 shape」を暗黙前提にしており、seize のような異形遷移が混在すると
  この前提が破れうる。

**KOB 側の対処方針:**

1. **凍結可能性を descriptor から事前判定する**(§4.4-3)。注文受付時に、担保資産の
   descriptor に issuer-authority extension が宣言されているかを検査し、宣言されて
   いる資産はエスクロー担保として扱う際にリスク開示 / 拒否 / 追加ヘッジのいずれかの
   ポリシーを適用する。凍結可能性が機械判読可能であることが、この事前判定の前提。
2. **seize 発生時の settle 経路を明示設計する**。エスクロー中に seize されうる前提で、
   settle が「担保消失」を検知して注文を明示的に fail-close(沈黙死させず、資金を
   返せる範囲で巻き戻す)する経路を持たせる。
3. **異形遷移 shape の混在に対する防御**(ISSUE-15 の恒久対策)。sibling state の
   読みを固定オフセット前提にせず、witness / descriptor 由来の shape 記述に基づいて
   分岐する。

要するに、KOB にとってステーブルコイン対応は「発行する側(issuer covenant を実装)」
と「担保に取る側(DEX が freeze 付き資産を安全に扱う)」の両面があり、後者の座礁
リスクは前者の機能(seize)の直接の帰結である。両者を貫くのが「凍結可能性の
descriptor 機械判読可能性」であり、これが本レポートの KCC 提案(§4.4)と KOB 実装の
接点になる。



## 6. 出典

### 6.1 リポジトリ内で直接裏取りした一次ソース(file:line)

- **KCC-0020 仕様原文** — `Fungible Token Covenant Specification (KCC20)`, Draft,
  Authors: Manyfest / Michael Sutton / IzioDev, 2026-07-15。
  Comments-URI: `https://kas-smiths.org/t/fungible-token-covenant-specification-kcc20/8/`
  (state ヘッダ / transfer interface / descriptor / Borrowed Receive v1 / extensions
  機構)。
- **KCC-0001 仕様原文** — `Covenant definition, concepts, bytes layout and ABI`,
  Draft, Authors: Romain Billot / Michael Sutton / Ori Newman(state 符号化 §8.1、
  template hash §8.3、continuation §8.5、P2SH envelope §7、dispatch §6、conformance
  vectors §11)。
- **KIP-20 `Covenant IDs`** — `https://github.com/kaspanet/kips/blob/master/kip-0020.md`
  (§5 Script Engine Introspection、§5.4 `OpOutputCovenantId`、Split/One-to-Many
  パターン)。KCC-0001 §12 が参照する一次文献。
- **Kaspa consensus — reference input 非対応** —
  `consensus/core/src/tx.rs:254-269`(`Transaction` は `inputs` / `outputs` のみ、
  reference / read-only input フィールド無し)。
- **Kaspa txscript — introspection opcode は input 限定** —
  `crypto/txscript/src/opcodes/mod.rs:1500-1510`(`OpInputCovenantId` は非 input で
  `"only applies to transaction inputs"`)、`:1362`/`:1379`(`OpTxInputSpkLen` /
  `OpTxInputSpkSubstr` も同様)、`:1258`(`OpTxInputAmount`)、`:1270`(`OpTxInputSpk`)。
- **Kaspa txscript — `OpCheckSigFromStack`(オラクル attestation の材料、3.5)** —
  `crypto/txscript/src/opcodes/mod.rs:1634`(`OpCheckSigFromStack` 0xd7、スタック上の
  任意 32byte メッセージハッシュ+署名をトランザクション sighash と無関係に検証)、
  `:1645`(ECDSA 版 `OpCheckSigFromStackECDSA` 0xd8)。KOB は現状この opcode を使用
  していない(下記 KOB KCC-0020 実装の `transfer.rs` 該当箇所を参照)。
- **KOB covenant introspection 実装** — `kob/core/src/contract/opcodes.rs:99-111`
  (`OP_TXINPUTAMOUNT` 0xbe、`OP_TXINPUTSPK` 0xbf、`OP_TXOUTPUTAMOUNT` 0xc2、
  `OP_TXOUTPUTSPK` 0xc3、`OP_INPUTCOVENANTID` 0xcf、`OP_COVINPUTCOUNT` 0xd0、
  `OP_COVINPUTIDX` 0xd1、`OP_COVOUTCOUNT` 0xd2)。
- **KOB KCC-0020 実装** —
  `kob/core/src/contract/kcc20/mod.rs`(2 つの amount 読みの併存、L25-33)、
  `kcc20/state.rs`(`Kcc20State` 4 フィールド、`ENCODED_LEN=77`)、
  `kcc20/transfer.rs:130`(`KCC20_TRANSFER_MAX_N=4`)/ `:336-350`(cardinality
  `OP_VERIFY` 2 本)/ module doc(`State[]` 非符号化・delegator 認可の逸脱)、
  `kcc20/descriptor.rs`(descriptor は in-memory shape のみ、ワイヤ形式未定)、
  `kcc20/borrowed_receive.rs:2`(未実装 stub)、
  `kcc20/transfer.rs:62-67`(module doc「Second interpretation decision」— leader が
  `OpCheckSigFromStack` で全 consumed state 署名を検証する案(a)を明示的に不採用とし
  delegator 自己認可(b)を採用した経緯、3.5)、
  `kob/core/src/contract/token.rs:16-40`(現行 `token_unit` の amount=native sompi
  値マッピング、アドレス発見安定性の設計判断)。
- **KOB price attestation 配線(3.5 の KOB 対応差分の根拠)** —
  `kob/core/src/contract/spot/order.rs:95-113`(CANONICAL PRICE ATTESTATION コメント、
  sigScript に price を載せ `OpTxInputScriptSigSubstr` 0xbc で covenant が読む配線。
  `OpCheckSigFromStack` とは別 opcode であり、生データ読み出しであって署名検証では
  ない点に注意)。
- **KOB 既存課題レポート** — `kob/KCC20_ISSUES.md`。特に §5(issuer-authority /
  compliance 不在、§5.1 grep 0 件、§5.3 Manyfest / Max143672 スレッド引用、§5.4
  並行性、§5.5 `kcc20_issuer_authority_v1` 提案、§5.6 DEX エスクロー座礁)、
  ISSUE-19(cardinality / supply インフレ)、ISSUE-6/7(descriptor ワイヤ形式)、
  ISSUE-4/18(identifier_type 所有権検証)、ISSUE-15(delegator shape 前提)。
- **kas-smiths.org スレッド #8** — issuer policy 議論(Manyfest post #9「global
  state utxo を強制する token」、Max143672 post #20「additional spending branch」/
  post #21「two-phase transfer: pending / ready-to-spend」)。`KCC20_ISSUES.md §5.3`
  に逐語引用。

### 6.2 調査B(規制ステーブルコインの必須機能)の参照対象

以下は上流の調査B が根拠とした規制 / 実装で、本レポートは調査B の要約を統合して
いる(個別の一次 URL は調査B の成果物が正本):

- **GENIUS Act**(米 payment stablecoin 法)および 2026 年 FinCEN / OFAC NPRM —
  発行体に「block / freeze / reject の技術的能力」を義務化、"seize, freeze, burn"、
  利息付与の明示禁止。
- **MiCA**(EU)/ **NYDFS**(NY 州)ガイダンス — 準備金 1:1、償還権、mint/burn。
- **USDT(Tether)** — `destroyBlackFunds`(freeze → burn の 2 段階)、Owner 集中、
  累計約 44 億ドル凍結実績、pause 非実装。
- **USDC(Circle)** — ロール分離(`masterMinter` / `pauser` / `blacklister` /
  `rescuer`)、pause 実装、blacklist 型。

### 6.3 調査A(UTXO チェーンの発行体制御 6 類型)の参照対象

上流の調査A が分類した先行実装(個別の一次 URL は調査A の成果物が正本):

- **A** インデクサ / オーバーレイ合意 — Omni Layer(USDT-Omni)、Kaspa KRC-20 と同型。
- **B** reissuance token / group key — Liquid Issued Assets、Taproot Assets。
- **C** 必須 co-signer — Liquid AMP(Blockstream Green)、RGB PFA。
- **D** オンチェーン registry cell + covenant introspection —
  **Cardano CIP-113**(programmable tokens / denylist、ソート済み linked list、
  withdraw-zero パターン。**testnet / preview、監査未了、本番未実証**)、
  **Nervos CKB xUDT + RCE**(SMT + AdminList、Whitelist / Blacklist / Emergency
  Halt / PKI の 4 機能を RFC で明示。**mainnet 採用事例なし、本番未実証**)。
  Cardano の reference input は CIP-31 相当。
- **E** 発行体不在アルゴリズム型 — Ergo AgeUSD / Djed(freeze 概念なし)。
- **F** クライアントサイド検証 — RGB NIA / IFA(freeze 強制力ゼロ)。
- **G** Universe 非承認 — Taproot Assets の Tether USDT 実運用(base layer 強制力
  なし、介入点はオン / オフランプのみ)。

> 免責: CIP-113 と RCE は本レポート内で繰り返し明記した通り**いずれも本番実証が
> 無い**。パターン D を「UTXO ネイティブの唯一解」と記すのは設計上の分類であり、
> 実運用実績の裏付けではない。

