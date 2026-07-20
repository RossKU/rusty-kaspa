# KOB ステーブルコイン 運用 runbook(§7.6-3: コンプラ最低線)

対象: `STABLECOIN_FOUR_AXIS_AUDIT_2026-07-20.md` §7.2 の運用層(covenant 変更を伴わない
コンプライアンス執行)。covenant 側の GAP 充填(§7.6-00〜2)は同監査 §9 実装ログ参照。

Kaspa は **reference input を持たない**(`consensus/core/src/tx.rs`、introspection は自 tx の
input しか読めない)ため、CIP-113/Nervos-RCE 型の「共有 denylist を全 transfer が read-only 参照」は
移植不可(1 ブロック 1 転送に縮退)。したがってコンプラ執行の第一線は **covenant の既存能力
(全 TRANSFER が issuer OPS 共署名必須 / per-coin FREEZE / SEIZE / BURN)を運用で束ねる**方式。
構造対応(SMT root blacklist=§7.6-8)は反映ラグを許容できる段階で追加する。

---

## 1. アドレス blacklist(§7.2-1 運用版 — 即時・オンチェーン露出なし)

**原理**: stablecoin の TRANSFER は毎回 issuer の OPS attestation 署名を要求する
(`body.rs` の `OpCheckSigFromStack`)。**OPS 署名者が署名前に受取人を制裁照合すれば、実質
アドレス単位の即時遮断**になる(covenant を触らず、新規登録簿も不要)。

### 1.1 OPS 署名ゲート(第一線)
- OPS 署名オラクル(facilitator / 発行体署名サービス)は、各 TRANSFER の attestation に署名する**前**に:
  1. 支払いの受取人 owner_pubkey → アドレス を導出。
  2. 制裁リスト(OFAC SDN 等)+ 内部 denylist と照合。
  3. ヒットしたら**署名拒否**(=その TRANSFER は成立しない。owner + OPS の 2-of-2 認可モデルゆえ
     OPS 差し止めで停止)。
- 監査ログ: 拒否理由・対象アドレス・タイムスタンプを追記専用ログに記録(後日の説明責任)。
- 注意: これは **TRANSFER のみ**を止める。FREEZE/SEIZE/MINT/RAISE_CAP は別鍵で動く(§2 参照)。

### 1.2 保有コインの一括 FREEZE(第二線・確定遮断)
制裁対象が既に保有するコインは OPS ゲートでは動かせないだけで凍結はされていない。確定遮断は:
1. **indexer で対象アドレスの全保有 covenant コインを列挙**(covenant_id 系列 + owner_pubkey で走査)。
2. 各コインに **FREEZE バッチ**を発行(`op_type::FREEZE`、FREEZE 鍵単独、owner 同意不要)。
   - FREEZE は per-coin(`frozen_flag`)。列挙した UTXO ごとに 1 FREEZE tx(または束ねる)。
   - FREEZE 後、そのコインは TRANSFER/BURN 不能(`frozen_flag==0` fail-close)。UNFREEZE か SEIZE のみ作用。
3. 新規受領の追随: 制裁対象が**後から**受け取るコインは新規 MINT/TRANSFER successor で `frozen_flag==CLEAR`
   で生まれる(whack-a-mole)。→ §1.1 の OPS ゲートで新規受領先への TRANSFER を止めるのが本線。
   構造的な自動凍結が要る場合は SMT root blacklist(§7.6-8)へ。

### 1.3 runbook(手順化)
```
制裁通知受領
  → 内部 denylist に追記(即時、OPS ゲート発効)
  → indexer で対象の既存保有を列挙
  → 保有ありなら FREEZE バッチ(FREEZE 鍵、air-gap 承認)
  → 必要なら SEIZE(cold 2-of-3)で回収
  → 監査ログ記帳
```

---

## 2. Global pause(§7.2-2 / G7 — 形式 flag なし、運用 kill-switch)

covenant にオンチェーンの global-pause flag は無い(`STABLECOIN_ROBUST_DESIGN.md §11-iv` の設計判断:
プロトコル変更を避ける)。代替は**各署名者を 1 スイッチで同時停止する運用 kill-switch**:

| 停止対象 | 効果 |
|---|---|
| OPS 署名者 | TRANSFER 停止(owner+OPS 2-of-2 ゆえ) |
| MINT 鍵 | 新規発行停止 |
| cap_authority (cold 2-of-3) | RAISE_CAP/ANNOUNCE_CAP 停止 |
| FREEZE 鍵 | freeze/unfreeze 停止 |
| SEIZE / recovery (cold 2-of-3) | seize / migrate / rotate 停止 |

- **重要**: OPS 停止だけでは TRANSFER しか止まらない。FREEZE/SEIZE/MINT/RAISE_CAP は別鍵で動き続ける。
  全面停止は上表の**全署名者を同時に差し止める**こと。
- kill-switch は HSM/署名サービス側の「発行停止」フラグ 1 つに集約し、runbook で発火手順を固定。

---

## 3. 準備金 attestation anchor(§7.2-3 / G4/G6)

covenant 変更不要。**issuer が準備金監査ハッシュに署名し、軽量 tx で anchor** する。

### 3.1 anchor tx の形
- Kaspa は bare `OP_RETURN`(0x6a)出力を mempool 非標準として弾く(既知、BURN sink で実証済)。
  → **`P2SH(<OP_RETURN payload>)` 型の unspendable 出力**に reserve-hash をコミットする、または
  発行体鍵の P2PK 出力 + 別途公表(hash を off-chain 公示し tx で時刻証明)。
- payload = `Blake3( reserve_report || period || issuer_sig )`。issuer 鍵で署名し、定期(日次/週次)に broadcast。
- covenant コインには一切触れない(別 funding UTXO から手数料)。

### 3.2 net supply の算出(G6)
- `running_supply` は**総発行量のみ**で BURN を差し引かない(net supply 不明)。
- **net_supply = running_supply − 累積 burn**。累積 burn は indexer が BURN sink(`op_type::BURN`)への
  spend を追跡して集計。準備金 attestation にはこの net_supply を含めて公表する。
- 用語注意: 本コードの「attestation」は per-spend 認可署名であって準備金証明ではない(別物)。

---

## 4. 鍵漏洩時の緊急対応(§7.3 / G0 と連動)

covenant 側で復旧 quorum は SEIZE と分離済み(§7.6-0、`recovery_pubkeys`)。運用手順:
- **SEIZE 鍵漏洩**: recovery quorum(独立 cold 2-of-3)は無傷 → 影響コインを SEIZE で発行体管理下へ →
  MIGRATE(recovery quorum)で健全 covenant へ移送。SEIZE 鍵はローテーション(ROTATE 実装後=§7.6-7)。
- **MINT 鍵漏洩**: cap 上限(§7.6-2 の checked `OpMul` ceiling)+ epoch 予算で被害上限。全面 pause(§2)後、
  MINT 鍵ローテーション。cap 承認済み raise が漏洩鍵で grief されない(§7.6-2 の state-anchored timelock)。
- **OPS 鍵漏洩**: OPS 停止(§2)で TRANSFER 全停止。OPS 鍵ローテーション。
- cold quorum は air-gap・複数カストディで事前プロビジョニング。

---

## 5. 実装状況と次段

- **本 runbook で足りる範囲**: 即時制裁遮断(OPS ゲート)、確定遮断(FREEZE バッチ)、pause、準備金公示。
- **コード化推奨(follow-on)**: (a) OPS 署名オラクルの denylist 照合フック、(b) indexer の
  「アドレス→保有コイン列挙」+ FREEZE バッチ生成、(c) 準備金 anchor tx ビルダ(`P2SH(OP_RETURN)`)、
  (d) net_supply 集計(burn 追跡)。いずれも covenant 非依存。
- **構造対応(§7.6-8 SMT root blacklist)**: 反映ラグを許容できる段階で、denylist を Sparse Merkle Tree 化し
  root を state に焼く。送金時に受取人の non-membership proof を sigScript で提示、covenant が自 state root に対し
  検証。共有参照 UTXO が不要=並列性ボトルネックゼロ。即時性は per-coin FREEZE で補完(併用)。
