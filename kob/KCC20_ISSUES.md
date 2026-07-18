# KCC-0020 実装課題抽出報告

KOB (kob-phase0) が KCC-0020 draft (`kcc-0020.md`) を準拠実装する過程
(`kob/core/src/contract/kcc20/`) で実際に手を動かして突き当たった仕様上の
課題を、kaspanet/kccs の仕様議論 (PR #2 = kcc-0020, PR #3 = kcc-0001,
kas-smiths.org スレッド #8) に提出できる形にまとめたものである。

対象読者: kaspanet/kccs メンテナ (Manyfest, IzioDev, michaelsutton ほか)。

## 1. 要旨

KOB は Kaspa L1 covenant orderbook DEX であり、KCC-0020 (Fungible Token
Covenant Specification, draft) を自前トークン実装 (`kob/core/src/contract/
kcc20/`) として準拠実装する作業を行った。実装は kcc-0020 自体に加え、その
下位レイヤーである KCC-0001 (Covenant definition, concepts, bytes layout
and ABI) と KIP-20 (Covenant IDs) にも同時に依拠する。

その過程で、(a) kcc-0020 の疑似コードを kcc-0001 の ABI 規則に忠実に従っ
て文字通り実装しようとすると実装不能になる箇所、(b) 仕様が意図的に/非意
図的に規範を与えていない箇所、(c) 実装のために KOB が独自の設計判断を行
い、その判断自体が仕様へのフィードバックになりうる箇所、の 3 種類の課題
が計 19 件抽出された。これに加えて、KOB が並行して進めている x402 決済
統合 (`kob/x402/`) の実運用要求から見えた descriptor 標準化の必要性(章
4)と、現実の USD ステーブルコイン発行に必須の issuer-authority /
compliance 機能が仕様に一切存在しないという構造的な欠落(章5)を、独立し
た章として提出する。

本報告の性質について明記しておく。19件の ISSUE はいずれも「KOB が
kcc-0020 を字面通り実装しようとして実際に手が止まった、または仕様と異な
る設計判断をせざるを得なかった」という一次資料(コードの doc comment・
TODO・テストの意図)に基づく。誇張や仕様への一方的な断定は避け、各 ISSUE
は (1) 仕様の該当引用、(2) KOB のコード上の解釈・回避策とその file:line、
(3) 提案、の3点セットで記載する。KOB 自身の設計判断が「仕様からの逸脱」
であることは全 ISSUE で隠さず明記しており、これは仕様側の欠陥だと決めつ
けるものではなく、実装者コミュニティとして仕様側と合意すべき論点の提示
である。

19件のうち特に重要度が高いと考えるのは次の3件である:

- **ISSUE-1 / ISSUE-11**(`State[]` が KCC-0001 §5.5/§5.6 のもとでエンコー
  ド不能): `transfer(State[] next_states, ...)` の `State[]` は、record
  配列の全 leaf が正の固定幅 payload を持たねばならないという §5.5/§5.6
  の要件と、`amount: int` が引数としては可変幅 (`PushMinimal` over
  minimal ScriptNum) にしかなり得ないという §5.3 の規定が正面衝突してお
  り、字面通りのエンコードが原理的に不可能である。KOB はこれを「successor
  の完全な redeem-script blob をまるごと引数として渡す」設計で代替した
  (`transfer.rs`)。これは kcc-0020 の宣言する型そのものからの必然的な逸
  脱であり、他の実装者も同じ壁にぶつかるはずである。
- **ISSUE-19**(cardinality 上限の仕様欠落): Kaspa Script にループがない
  以上、あらゆる実装は N-of-N 検証を固定境界に unroll せざるを得ないが、
  kcc-0020 にはこの境界を超えた consumed input / produced output をどう
  扱うべきかの規範が一切ない。境界超過分を明示的に reject しない実装は、
  境界外に置かれた token 入力が保存則チェックを素通りし、額面のインフレ
  ーションを許してしまいうる。KOB は明示的な cardinality 上限チェックで
  これを防いでいるが、この防御自体が仕様に要求されていない、実装者依存
  の任意対応になっている。
- **ISSUE-15**(sibling 固定オフセット読みの暗黙 shape 前提): leader が
  delegator (sibling) 入力の `amount`/`extended_state_digest` を
  `OpTxInputScriptSigSubstr` で固定バイトオフセットから読む設計
  (`sibling_field_offsets`)は、「あらゆる delegator の sigScript は
  `push_data(sig) || OP_DATA_4 tag || PushMinimal(R)` という一様な形をし
  ている」という暗黙の shape 契約に依存している。この契約は仕様がどこに
  も明文化しておらず、kcc-0020 自身が定義する KCC20 Borrowed Receive
  Extension v1(所有者の署名協力なしに successor を再利用する拡張)を実
  際に配線した瞬間に破綻する — borrowed 入力は定義上 owner 署名を持たな
  いため、この一様 shape 前提が最初に崩れる具体例そのものである。

## 2. Severity 別 ISSUE 一覧表

Severity 内訳: **HIGH 5 件 / MEDIUM 10 件 / LOW 4 件**(計19件)。

| # | タイトル | Severity | 対象仕様 | 種別 |
|---|---|---|---|---|
| 1 | `State[]` が KCC-0001 §5.5/§5.6 の下でエンコード不能(record 配列の固定幅 leaf 制約と `int` 引数の可変幅の衝突) | **HIGH** | kcc-0020 Transfer Interface / kcc-0001 §5.3,5.5,5.6 | 仕様間の正面衝突 |
| 2 | `amount` の範囲: Rust `u64`(0..2^64-1) vs KCC1 `int` 8byte 符号絶対値表現(最大 2^63-1) | MEDIUM | kcc-0001 §5.3 | 仕様規範の実装制約 |
| 3 | 負の `amount` / negative zero の正準性が未定義 | LOW | kcc-0001 §5.3/§5.4, kcc-0020 State | 規範欠落 |
| 4 | `identifier_type` = SCRIPT_HASH / COVENANT_ID の所有権検証規則が未定義 | MEDIUM | kcc-0020 State | 規範欠落(PR 係争中) |
| 5 | `signatures[]` と `witnesses[]` を分離する設計意図が不明瞭 | LOW | kcc-0020 Transfer Interface | 設計意図不明(PR 係争中) |
| 6 | `KCC20Descriptor` のワイヤ形式が皆無 | **HIGH** | kcc-0020 Descriptor | 規範欠落・相互運用ブロッカー |
| 7 | `ExtensionId` のエンコード形式が未定義 | MEDIUM | kcc-0020 KCC20 Extensions | 規範欠落 |
| 8 | 非正準 push を MUST-reject すべきかが未規定(実チェーン実測あり) | MEDIUM | kcc-0001 §8.1 | 規範欠落(実測データあり) |
| 9 | dispatch tag はエントリポイント数を知らないパッシブな観測者には判別不能 | MEDIUM | kcc-0001 §6.1/§7 | 設計上の undecidability(実測データあり) |
| 10 | `PushMinimal`/`PushExplicit` の payload 長 2^32 超過時の挙動が未定義 | LOW | kcc-0001 §5.2 | 規範欠落(理論上の境界) |
| 11 | `next_states: State[]` を redeem-script-blob 方式で代替(ISSUE-1 の実装側帰結) | **HIGH** | kcc-0020 Transfer Interface | 仕様からの必然的逸脱 |
| 12 | `transfer_delegator()` の「引数ゼロ」が実装不能で自己認可署名を追加 | MEDIUM | kcc-0020 Transfer Interface | 仕様からの必然的逸脱 |
| 13 | `extended_state_digest` の一致範囲(部分統合時の対応関係)が曖昧 | LOW | kcc-0020 Transfer Interface | 規範欠落 |
| 14 | 基本 `transfer` における `witnesses[]` の意味論が未定義(拡張以外の用途不明) | MEDIUM | kcc-0020 Transfer Interface | 規範欠落 |
| 15 | sibling 固定オフセット読みが delegator sigScript の一様 shape を暗黙前提化(Borrowed Receive で破綻) | **HIGH** | KOB 実装設計(kcc-0020 Borrowed Receive Extension v1 と相互作用) | セキュリティ上の暗黙契約 |
| 16 | dr 系ヘルパのスタック深度規約が未文書化で実装時に暗黙の罠になった | MEDIUM | KOB 内部実装規律の欠如 | 実装リスクパターン |
| 17 | `int` state payload の非最小性 enforcement がエンジンの `covenants_enabled` フラグに依存 | MEDIUM | kcc-0001 §5.3 / エンジン実装 | 仕様が触れないエンジン挙動依存 |
| 18 | `identifier_type` の実装は PUBKEY のみ(SCRIPT_HASH/COVENANT_ID は未実装) | MEDIUM | kcc-0020 State | 実装スコープ制限(ISSUE-4 と表裏) |
| 19 | cardinality(consumed input / produced output数)の上限が仕様に存在せず、無検証だと保存則を回避しうる | **HIGH** | kcc-0020 Transfer Interface | 規範欠落・セキュリティ |

章4(x402)・章5(issuer-authority/compliance)は上記 19 件のカウントに含
めない独立の構造的ギャップとして提出する(章4は ISSUE-6 の帰結を具体ユー
スケースで補強するもの、章5は仕様全体に対する機能追加提案)。

## 3. ISSUE 詳細

### ISSUE-1 — `State[]` は KCC-0001 の下でエンコード不能(HIGH)

**仕様引用**

kcc-0020 "## Transfer Interface":

```text
transfer(
    State[] next_states,
    sig[] signatures,
    byte[] witnesses
)
```

kcc-0001 §5.5 (Arrays): 「A dynamic array `T[]` is permitted only when `T`
has a fixed payload width, width(T) > 0.」

kcc-0001 §5.6 (Records): 「An array of records is permitted only when
every recursively lowered leaf field has a positive fixed payload width.」

kcc-0001 §5.3 (Integers): 「An `int` invocation argument uses
`PushMinimal` over its minimal ScriptNum representation.」(= 引数として
の `int` は可変幅。固定8byte幅になるのは **state payload** としての
`int` のみ、§5.3後段。)

**KOB の解釈・回避(file:line)**

`kob/core/src/contract/kcc20/dispatch.rs:19-54`(module doc、
`TRANSFER_FUNCTION_SIGNATURE` の直前)が、この矛盾を最初に文章化した箇所
である:

> "an array of records is only valid when every recursively lowered leaf
> field has a POSITIVE FIXED payload width, but `State.amount` is an
> `int`, and kcc-0001 §5.3/§5.4 give `int` a FIXED 8-byte width only in
> its STATE-payload form — as a standalone ARGUMENT (which is what
> `next_states` is, being `transfer`'s invocation data), `int` uses
> `PushMinimal` over a *minimal ScriptNum* representation, which is
> explicitly VARIABLE-width."

さらに kcc-0020 自体が record 型 `State` を §5.6 の意味で正式宣言してい
ない(見出し「## State」の下に4フィールドを prose で列挙しているだけで、
`TypeName(T)[] = "State"` という record 名の宣言がない)ことも同モジュー
ル doc で指摘している。dispatch tag 計算のためだけに `"State"` という名
前を仮採用しているが、これは PR レビューで実際に別名(`KCC20State`)も
使われており(dispatch.rs 中のコメントで言及)、命名自体が定まっていな
い。

この矛盾は record lowering をどう工夫しても解消しない: `amount` を配列の
末尾に置く、`int` を先に固定長 `byte[8]` に変換する、といった re-encode
は kcc-0001 が規定する `State[]` の型そのものの解釈を変えることになり、
「仕様が書いている型を字面通り実装する」という前提が最初から成立しない。

**提案**

- kcc-0001 側で「配列内の record が可変幅 leaf を持つ場合の許容エンコー
  ド(要素ごとに独立した push 列に展開する、など)」を追加するか、
- kcc-0020 側で `State` を正式に record として宣言した上で `amount` を
  引数コンテキストでは固定8byte幅の `byte[8]` として再定義するか、
- あるいは `next_states` 自体を「各要素をまるごと独立引数として渡す」設
  計(ISSUE-11 で KOB が実際に採用した代替設計)に仕様側を寄せるか。
いずれかの選択を PR #2/#3 の場で明示的に決定することを提案する。

### ISSUE-2 — `amount` の範囲: `u64` vs KCC1 `int` の 2^63-1 上限(MEDIUM)

**仕様引用**

kcc-0020 "## State": `amount: integer`。

kcc-0001 §5.3 (Integers): 「The KCC1 `int` range is:
`-(2^63 - 1) <= value <= 2^63 - 1`」「An `int` state payload uses an
eight-byte little-endian signed-magnitude encoding.」

**KOB の解釈・回避(file:line)**

`kob/core/src/contract/kcc20/mod.rs:270-282`(module note、`KCC1_INT_MAX_
MAGNITUDE` 定義の直前)が根拠を説明している。8byte 符号絶対値表現は 1bit
を符号に使うため、表現可能な最大絶対値は `2^63-1`(`i64::MAX`)であり、
`u64::MAX`(2^64-1)全域を表現できない。`kob/core/src/contract/kcc20/
mod.rs:294-301` の `encode_uint_as_int_state_payload` はこの上限超過を
明示的にエラーとして reject する。

一方 `kob/core/src/contract/kcc20/state.rs:38-46` の `Kcc20State.amount`
は Rust 型として素朴に `u64` を採用しており(トークン数量として自然な選
択)、型システム上は `2^63` 以上の値を保持できてしまう — それをエンコー
ドしようとして初めて `encode_script()` がエラーを返す(`state.rs:207-
211` のテスト `amount_over_kcc1_int_max_magnitude_fails_to_encode` で確
認)。つまり「amount の Rust 表現域」と「amount の on-chain 表現可能域」
に2^63のギャップがあり、この不一致は実装者が気づかない限り encode 時ま
で顕在化しない。

**提案**

kcc-0020 の `amount: integer` は kcc-0001 の `int` 型を指すという前提を
明文化した上で、「発行総量が `2^63-1` sompi 相当を超えるトークンは
KCC-0020 のもとで表現できない」という上限を仕様本文に明記することを提案
する(現状は kcc-0001 の一般規定から間接的に導かれるのみで、kcc-0020 自
体はこの含意に触れていない)。

### ISSUE-3 — 負の `amount` / negative zero の正準性が未定義(LOW)

**仕様引用**

kcc-0001 §5.3 が定義する8byte符号絶対値表現には、数学的に同一の値
`0` に対して2通りのビット列(`00^8` = "positive zero" と
`00^7 || 80` = "negative zero")が存在しうる。kcc-0001 はこれについて何
も述べておらず、また kcc-0020 も `amount` が負値を取りうるか(トークン数
量として自然には非負のはずだが、明示の禁止がない)を規定していない。

**KOB の解釈・回避(file:line)**

`kob/core/src/contract/kcc20/mod.rs:315-320` の
`decode_int_state_payload` doc:「kcc-0001 does not say whether an encoder
must avoid emitting "negative zero" or whether a decoder must reject it」
と明記した上で、この汎用デコーダは両方の zero 表現を値 `0` として受理す
る(`mod.rs:562-568` のテストで two byte-strings, one value を確認)。

一方 `kob/core/src/contract/kcc20/state.rs:333-344`(`decode_uint_from_
int_state_payload`)は `Kcc20State.amount` 専用の非負限定デコーダとして、
符号bitが立っている入力を——たとえ絶対値が0の "negative zero" であって
も——一律に拒否する。`state.rs:251-260` のテスト
`decode_rejects_negative_amount` がこれを確認している。これは
「kcc-0020 が実際に禁止しているのか、KOB が独自に上乗せした制約なのか」
が判別できないまま実装したものであると `state.rs:93-96` のコード
コメントが明記している。

**提案**

kcc-0020 の `amount` フィールドに「非負整数(非負性は decoder が
MUST enforce する)」であることを明記し、あわせて kcc-0001 §5.3/§11.3
に「negative zero を encoder は emit してはならない(SHOULD NOT)」
「decoder は negative zero を受理してよいが、amount のような非負が前提
の semantic layer では追加のバリデーションが必要」という一文を加えるこ
とを提案する。

### ISSUE-4 — `identifier_type` = SCRIPT_HASH / COVENANT_ID の所有権検証規則が未定義(MEDIUM)

**仕様引用**

kcc-0020 "## State":

```text
IDENTIFIER_PUBKEY      = 0x00
IDENTIFIER_SCRIPT_HASH = 0x01
IDENTIFIER_COVENANT_ID = 0x02
```

「`identifier_type` defines how `owner_identifier` is interpreted.」—
*解釈方法*は定義されているが、`transfer` がその解釈値に対して**何を検証
すべきか**(= 所有権の証明方法)は、PUBKEY 以外について本文のどこにも書
かれていない。

これは PR #2 のレビューで実際に争点化している論点でもある。
`biryukovmaxim`(kcc-0020.md line 41 review, 2026-07-15/16)は ECDSA の
Y 座標符号 (`PubkeyEcdsaYNeg`/`PubkeyEcdsaYPos`) を含めた identifier
type の追加や、「covenant identifier に prefix/suffix 制約を持たせ
`hash(covenant, suffix, prefix)` を identifier にする」設計を提案し、
`Manyfestation`(同スレッド 2026-07-16)は「token ownership state は
単一の32byte hash になり、entrypoint はそれが pubkey/script_hash/cov_id/
ecdsa/cov_id_plus_template のどれであるかの hint(witness?)を提供すべ
き」という、`identifier_type` を静的な per-covenant enum ではなく
per-transfer 動的選択にする方向の再設計まで議論しており、**
`identifier_type` という概念自体の設計が確定していない**。

**KOB の解釈・回避(file:line)**

`kob/core/src/contract/kcc20/identifier.rs` 全体(特に module doc
1-31行)。`emit_ownership_check()`(69-97行)は `PUBKEY`(behaviorally
unambiguous — `owner_identifier` がそのまま32byte Schnorr公開鍵)のみ
`OpCheckSigVerify` を発行して実装し、`SCRIPT_HASH`/`COVENANT_ID` は
`IdentifierVerificationError::VerificationRuleUndefined` を返す明示的な
未実装として区別している(推測でビットコードを埋めることを意図的に避け
た、と module doc 24-31行に明記)。

**提案**

`identifier_type` ごとの検証規則(最低限 SCRIPT_HASH: どの入力/UTXO の
script hash と照合するか、COVENANT_ID: `OpInputCovenantId` とどう突き合
わせるか)を kcc-0020 本文に明記することを提案する。あわせて、
Manyfestation の「動的 hint 化」提案が採用されるかどうかで `transfer`
の引数シグネチャ自体が変わりうるため(ISSUE-5 とも関連)、この論点は
`State[]` の record 定義(ISSUE-1)より先に決着させることを推奨する。

### ISSUE-5 — `signatures[]` と `witnesses[]` を分離する設計意図が不明瞭(LOW)

**仕様引用**

kcc-0020 "## Transfer Interface":

```text
transfer(
    State[] next_states,
    sig[] signatures,
    byte[] witnesses
)
```

「`signatures`: authorization signatures corresponding to consumed
states; and `witnesses`: per-input authorization metadata required for
consumed states.」— 両者がなぜ別配列として分離されているのか、両者の
関係(1対1対応か、witnessesがsignaturesの解釈ヒントか)は本文で明示さ
れていない。

**PR #2 での実際の議論**

`biryukovmaxim`(kcc-0020.md line 52, 2026-07-15):「what is the reason
to distinguish signatures from witnesses, why not pass signatures as
part of witnesses.」

`Manyfestation` の応答(2026-07-16):「Witness was meant to be used as a
metadata artifact to add context to the input spend authentication. For
example, in the case of a p2sh ownership, the witness would represent
the index of the p2sh input, and the transfer fn would only verify that
`tx.inputs[witness].p2sh == owner_id`.」「I imagined that the combination
of them would allow extending the authentication of a spend, that a
tuple of `(sig, witness)` could be used like `(proof, metadata/type)`...
I have some unresolved thoughts about this though.」— 提案者自身が
「unresolved」と認めている、係争中の設計である。

**KOB の解釈・回避(file:line)**

KOB は `signatures[]`/`witnesses[]` を kcc-0020 が宣言する形のまま実装
していない。`kob/core/src/contract/kcc20/transfer.rs:54-95`(module
doc「Second interpretation decision: delegator authorization」)が経緯
を記録している: leader 側の `signatures[]` は「1エントリ = leader 自身
の認可署名のみ」に狭められ(全 consumed state 分ではない)、各 delegator
は自分自身の sigScript で自己認可する設計(decision (b))を採用した。
`witnesses[]` は base transfer 経路では一切配線されていない(ISSUE-14
参照)。

**提案**

`(sig, witness)` を `(proof, metadata/type)` のペアとして扱うという
Manyfestation の構想を仕様として確定させるか撤回するかを PR の場で決着
させ、確定した場合は「witness がどんな値を取り、`transfer` がそれをどう
解釈するか」の最低限のレジストリ(現状 Borrowed Receive の
`BORROWED_RECEIVE = 0xFF` のみが具体値を持つ)を本文に追加することを提
案する。

### ISSUE-6 — `KCC20Descriptor` のワイヤ形式が皆無(HIGH)

**仕様引用**

kcc-0020 "## Descriptor":

```text
KCC20Descriptor {
    prefix: bytes
    suffix: bytes
    extended_state_layout: ExtendedStateLayout | none
    kcc20_extensions: ExtensionId[]
}
```

「The descriptor must be published so tooling can identify the covenant,
decode its state, reconstruct its outputs, and determine which KCC20
extensions it supports.」— *公開されなければならない*とは書かれている
が、どういうバイト形式で、どこに公開するのかは一切規定されていない。

**KOB の解釈・回避(file:line)**

`kob/core/src/contract/kcc20/descriptor.rs:12-34`(module doc全体)が
ギャップを列挙している:

> "no field order convention (is it KCC1 §5.6 record-lowered? Over what
> push encoding?), no length-prefixing for `prefix`/`suffix`, no
> discriminant for `ExtendedStateLayout | none`, no encoding for
> `ExtensionId`... kcc-0020 only says "The descriptor must be published
> so tooling can identify the covenant" -- "published" how, and in what
> byte format, is unspecified."

kcc-0001 が state encoding・template hash・dispatch tag・virtual element
のすべてに §11 で byte-exact な conformance vector を用意しているのと
対照的に、kcc-0020 の Descriptor だけがこの慣行から外れている。

KOB はこのギャップを「独自のワイヤ形式を発明して埋める」ことを意図的に
避け、`Kcc20Descriptor` を **encode/decode を持たないメモリ上の Rust
shape のみ**として実装した(descriptor.rs:26-34: 「inventing a wire
format here would just be KOB's own private convention masquerading as
spec conformance」)。

**提案**

kcc-0020 に、少なくとも以下を含む descriptor のワイヤ形式(または
シリアライズ形式選定の指針)を追加することを提案する:
- `prefix`/`suffix` の長さプレフィックス方式、
- `ExtendedStateLayout | none` の discriminant、
- `ExtensionId` の正準エンコード(固定長タグか UTF-8 文字列か)、
- 「公開」の実務的な既定経路(on-chain payload か、artifact ファイルか、
  レジストリ URL か)。

章4(x402)で述べる通り、この欠落は理論上の整理不足に留まらず、外部発行
トークンを受け入れる決済ユースケースの直接的なブロッカーになっている。

### ISSUE-7 — `ExtensionId` のエンコード形式が未定義(MEDIUM)

**仕様引用**

kcc-0020 "## KCC20 Extensions": 「Supported extensions must be declared
by their versioned `ExtensionId` in the descriptor's `kcc20_extensions`
field.」現在唯一定義済みの拡張の ID は文字列様の識別子
`kcc20_borrowed_receive_v1` として例示されているのみで、`ExtensionId`
という型そのものの正準エンコード(UTF-8 文字列か、dispatch tag に類する
固定長ハッシュ値か)は本文のどこにも型定義されていない。

**KOB の解釈・回避(file:line)**

`kob/core/src/contract/kcc20/descriptor.rs:23-25`(module doc)で
明示的に「no encoding for `ExtensionId` (are these UTF-8 strings? Fixed
4-byte tags analogous to a dispatch tag...)」と指摘。

`kob/core/src/contract/kcc20/borrowed_receive.rs:85-86` の
`KCC20_BORROWED_RECEIVE_V1: &str = "kcc20_borrowed_receive_v1"` は
kcc-0020 の例示文字列をそのまま Rust の `&str` 定数として転記したのみ
で、これを実際に descriptor のワイヤ上でどう表現するかは決めていない
(descriptor.rs:76-82 の `kcc20_extensions: &'static [&'static str]` も
同様、in-memory shape のみ)。

**提案**

`ExtensionId` を kcc-0001 の dispatch tag と同様の「名前文字列から決定
的に導出される固定長タグ」として正式に型定義するか(例:
`Hash(UTF8(extension_name))[0:4]` のような既存パターンの転用)、あるい
は UTF-8 文字列そのものを正準ワイヤ表現とする(その場合は長さプレフィッ
クス方式も併せて規定)かを明確にすることを提案する。ISSUE-6 の descriptor
ワイヤ形式全体と合わせて解決するのが自然である。

### ISSUE-8 — 非正準 push を MUST-reject すべきかが未規定(MEDIUM、実測データあり)

**仕様引用**

kcc-0001 §8.1 (State encoding): 「The consumed bytes MUST exactly equal
`PushExplicit(payload)`. A decoder MUST also reject malformed pushes,
invalid payloads, missing fields, or trailing bytes.」— これは **state**
の decode に関する MUST であり、**invocation 引数**(`PushMinimal`)側の
非正準 push を decoder が reject すべきかについては明文の規定がない。

**PR #3 での実測(Knitser, kcc-0001.md issue comment, 2026-07-18)**

kascov プロジェクトが独自に同種の規約を実装してきた立場から実チェーン
データを計測した上でのコメント: 「Non-minimal pushes exist in compiler
output today. Should decoders MUST-reject them? Happy to measure
on-chain compliance if that helps decide.」実際にコンパイラ生成コードで
非正準 pushが観測されている、という一次情報付きの未決論点提起である。

**KOB の解釈・回避(file:line)**

`kob/core/src/contract/kcc20/mod.rs:143-203`(`decode_push_explicit`)
と `mod.rs:205-268`(`decode_push_minimal`)は、いずれも非正準エンコー
ド(例: 32byte payload を `OP_PUSHDATA1` で押す、1byte payload を
`OP_DATA_1` で押す等)を無条件に `None` として reject する、最も厳格な
解釈を採用している(`mod.rs:150-153` のコメントで根拠を kcc-0001 §8.1
の MUST 文言に求めている)。ただしこれは **state** の decode についての
話であり、KOB 自身、invocation 引数側の非正準 push を実際に reject する
コードパスは(`transfer`/`transfer_delegator` の引数を「配列としては
decode せず、redeem-script-blob としてそのまま扱う」設計— ISSUE-11 —の
ため)そもそも持っていない。

**提案**

kcc-0001 §5.2/§6.2 に、invocation 引数側の非正準 push に対する decoder
の義務(MUST reject / MAY accept)を明記することを提案する。Knitser が
「measure on-chain compliance if that helps decide」と申し出ている通
り、実測データに基づいて決定できる状態にあるため、決定自体を先送りする
理由は薄いと考える。

### ISSUE-9 — dispatch tag はエントリポイント数を知らない受動的観測者には判別不能(MEDIUM、実測データあり)

**仕様引用**

kcc-0001 §7 (P2SH Covenant Envelope): 「The bracketed dispatch-tag
element MUST be omitted for a program with exactly one entrypoint. For a
program with two or more entrypoints, it MUST be present...」— この
「1エントリポイントなら省略、2つ以上なら必須」という条件分岐は、
signature script を書く側(covenant のプログラム ABI を知っている側)
には自明だが、**それを外部から受動的に観測するだけの主体**(インデクサ
・ブロックエクスプローラ・チェーン監視ツール)にとっては、対象の
covenant が何エントリポイントかを事前に知らない限り、末尾から2番目の
4byte要素が「dispatch tag」なのか「たまたま4byteの末尾引数」なのかを
判別する手段がない。

**PR #3 での実測(Knitser, kcc-0001.md issue comment, 2026-07-18)**

kascov による実チェーン計測: 「as an external observer we scanned
867,456 spent covenant sigscripts on testnet-10 for the tag shape
(penultimate OP_DATA_4 push). Zero matches today, only 17,616 sigs have
2+ pushes at all, so no legacy shape to accommodate.」その上で:
「"tag omitted iff exactly one entrypoint" means a passive decoder can't
distinguish a tag from a trailing 4-byte argument without knowing the
entrypoint count, so having the future artifact format carry that count
would make the identification... fully decidable.」

**KOB の解釈・回避(file:line)**

`kob/core/src/contract/kcc20/p2sh.rs:62-71`(`parse_sigscript` の doc)
がこの限界を明記している: 「kcc-0001 does not define a self-delimiting
encoding for "where the argument region ends" in general... a real
decoder needs the Program ABI's argument type list to know
`arguments_len` up front, exactly as this function requires it as a
parameter.」KOB の `parse_sigscript` はまさにこの理由で `arguments_len`
を呼び出し側が別途知っている前提の関数シグネチャになっており(72-79行)、
sigScript バイト列単独からの自己完結的な decode を提供していない。
KCC20 は固定2エントリポイントなので KOB 自身は問題に直面しないが
(`p2sh.rs:12-15`)、これは KCC20 固有の特殊ケースであり、一般の
kcc-0001 準拠 covenant には解決策になっていない。

**提案**

Knitser の提案通り、将来の artifact format(Program ABI の配布形式)に
「このプログラムのエントリポイント数」を明示フィールドとして含めること
を kcc-0001 の非規範的ノートとして追加することを提案する。これにより受
動的観測者が「tag の有無」を artifact 側の情報と突き合わせて decidable
に判定できるようになる。

### ISSUE-10 — `PushMinimal`/`PushExplicit` の payload 長 2^32 超過時の挙動が未定義(LOW)

**仕様引用**

kcc-0001 §5.2 (Data pushes) の表の最終行: 「`65536 <= n <= 2^32 - 1` →
`OP_PUSHDATA4 || LE32(n) || b`」。表はここで終わっており、
`n > 2^32 - 1` の場合にどう振る舞うべきか(そのような payload は
そもそも invalid なのか、別の form が必要なのか)は明記されていない。
`LE32` が 32bit である以上、長さそのものを表現する手段が表の中に存在し
ない。

**KOB の解釈・回避(file:line)**

`kob/core/src/contract/kcc20/mod.rs:112-141`(`push_length_based`)の
`match n { ... _ => { ... OP_PUSHDATA4 ... } }` アーム(128-137行)の
コメント: 「kcc-0001's last row caps at 2^32-1. `n` is a Rust `usize`
(64-bit on this build's target); a payload with n > u32::MAX is not a
valid PushMinimal/PushExplicit length under kcc-0001 at all... so we do
not special-case it.」KOB は「2^32 を超える長さはこの crate の実用上遭
遇しない」という前提で明示的なエラー処理を行わず、`n as u32` の
truncating cast に委ねている(理論上、2^32 を超える payload を誤って渡
すと長さ情報が silently truncate される)。

**提案**

kcc-0001 に「payload 長は `2^32 - 1` を超えてはならない(MUST NOT)」
という上限を明文化し、超過時に encoder が何をすべきか(エラーを返す、
など)を規定することを提案する。理論上の境界であり実害の実測はないが、
表の暗黙の前提を明文化するだけの軽微な追記で足りる。

### ISSUE-11 — `next_states: State[]` を redeem-script-blob 方式で代替(HIGH、ISSUE-1の実装側帰結)

**仕様引用**

kcc-0020 "## Transfer Interface"(再掲): `transfer(State[] next_states,
sig[] signatures, byte[] witnesses)`。「`next_states`: the states created
by the transfer, ordered by covenant output index」。

**KOB の解釈・回避(file:line)**

ISSUE-1 で述べた通り `State[]` は kcc-0001 の下でエンコード不能なため、
`kob/core/src/contract/kcc20/transfer.rs:1-52`(module doc)は
`next_states` を **配列として一切エンコードしない**設計を採用した。代
わりに、KOB が既存に持っていた「successor covenant program をまるごと
認証する」パターン(`crate::contract::dr`、`spot::dca` の D&R ステップ
で既に使用)を転用し、各 successor を「まるごとの redeem-script blob」
(`new_rs_k`、出力スロット `k` の完全な候補 `R`)として渡す:

1. leader は自分自身の現在の redeem script(`self_rs`、`R` のもう一つの
   コピーを平引数として渡す)を、実際に消費される入力の P2SH commit ハ
   ッシュと照合して認証する(`dr_input_spk_check`、transfer.rs:352-356)。
2. 有効な各 successor スロット `k` について、`new_rs_k` の suffix が
   `self_rs` の suffix とバイト同一であることを検証する
   (`dr_suffix_check`、transfer.rs:407-411 コメント参照 — kcc-0001
   §8.5 が要求する template 認証そのもの)。
3. 実際の output が `new_rs_k` にハッシュすることを検証する
   (`dr_output_spk_check`)。
4. `new_rs_k` の `amount`/`extended_state_digest` を固定バイトオフセッ
   トから抽出する(transfer.rs:182-207 の固定オフセット定数群)。

これは kcc-0020 の宣言する `State[]` 引数型そのものからの逸脱であり、
transfer.rs:44-52 で「a deviation from kcc-0020's literal `State[]`
argument type... `next_states` as declared cannot be implemented; "a
list of whole successor redeem scripts" is the substitute this wave
ships」と明記している。

**提案**

ISSUE-1 の解決と対にして、`next_states` の正準表現を「各要素を独立した
引数(successor プログラム全体、または最低限 amount/digest を固定幅
byte 列としてパックしたもの)として渡す」設計に仕様側を合わせることを
提案する。KOB のような「successor 全体を認証する」パターンは Kaspa
Script にループがない制約下では自然な設計であり、既に他の KOB 機能
(`dr` モジュール)で実績があるため、参考実装として提供可能である。

### ISSUE-12 — `transfer_delegator()` の「引数ゼロ」が実装不能(MEDIUM)

**仕様引用**

kcc-0020 "## Transfer Interface": 「`transfer_delegator()`」— 引数リス
トが空である。「Each remaining KCC20 covenant input invokes
`transfer_delegator` with no input data to join the transfer declared by
the leader.」

**KOB の解釈・回避(file:line)**

`kob/core/src/contract/kcc20/transfer.rs:54-95`(module doc
「Second interpretation decision: delegator authorization」)が問題を
提起している: Kaspa Script には「leader が既にこの group の全入力を認
可した」という概念がなく、各入力は**自分自身の**支出スクリプトが独立に
true を返さねばならない。2つの設計を検討した:

- (a) leader-verifies-all: leader の `signatures[]` が全 consumed state
  分の署名を持ち、`OpCheckSigFromStack` で他入力の支出を検証する —
  この opcode は kcc-0001 に一切登場せず、「他入力の支出を認可する署名」
  のメッセージハッシュ規約も定義されていないため、仕様に書かれていない
  プロトコルを独自発明することになると判断し不採用。
- (b) delegator-self-authorizes: 各 delegator 入力が自分の sigScript か
  ら自分の owner 認可を独立に証明する。KOB は **(b) を採用**。

結果として `build_transfer_delegator_body()`(transfer.rs:280-304)は、
delegator の sigScript に **65byte の `self_sig` を実引数として要求す
る**(transfer.rs:79-88: 「a delegator's sigScript here pushes one
65-byte `sig` — that is real, consumed invocation data, not
spec-conformant "no input data"」)。これは
`transfer_delegator()` の「zero arguments」宣言そのものからの必然的な
逸脱である。

**提案**

`transfer_delegator()` の引数リストを、実装上ほぼ必然的に必要になる
「この入力自身の認可署名」を明示的な引数として仕様に追加することを提
案する(例: `transfer_delegator(sig self_signature)`)。「引数ゼロ」を
文字通り維持したい場合は、代わりに leader 側検証方式(前述の (a))を
仕様として正式に定義し、そのために必要な opcode・メッセージハッシュ規
約を kcc-0001 に追加する必要がある。

### ISSUE-13 — `extended_state_digest` の一致範囲(部分統合時の対応関係)が曖昧(LOW)

**仕様引用**

kcc-0020 "## Transfer Interface": 「When multiple inputs are
consolidated into one successor state, they must have the same
`extended_state_digest`.」

**KOB の解釈・回避(file:line)**

`kob/core/src/contract/kcc20/transfer.rs:97-111`(module doc
「`extended_state_digest` equality scope」)が指摘する通り、この一文は
「複数入力が1つの successor に統合される」ケースの対応関係のみを述べて
おり、**部分的な統合・分割が混在するケース**(例: 4入力のうち2つが
successor Aに、残り2つが successor Bに統合される)で「どの consumed
state がどの successor の digest と一致すべきか」の対応規則を与えていな
い。「一致すべきは *its own* predecessor(s)」という文言だけでは、
consumed-input <-> successor-output の対応関係が一意に定まらない。

KOB が採用した解釈(transfer.rs:104-111): **covenant-id group 全体で単
一の digest を共有する**(このtransferで consumed される全 state と
produced される全 state が同一の `extended_state_digest` を持たねばな
らない)。これは実務上過剰な制約にはならないと注記している —
KIP-20 の shared covenant-id context がトランザクション全体に対して
`covenant_id` 単位でグローバルであり、サブグループ化の仕組みが存在しな
い以上、同一 `covenant_id` の下で異なる extended state を持つ2つの独立
した統合グループがそもそも共存できないため。

**提案**

kcc-0020 に、「1トランザクション内で同一 `covenant_id` を共有する
transfer は、産出される全 successor state が同一の
`extended_state_digest` を持たねばならない(= サブグループ化は許されな
い)」という KOB の解釈を明文の規則として採用するか、あるいは
サブグループ化を許容する場合の対応規則(例: witness 経由で consumed/
produced のペアリングを明示する)を追加することを提案する。

### ISSUE-14 — 基本 `transfer` における `witnesses[]` の意味論が未定義(MEDIUM)

**仕様引用**

kcc-0020 "## Transfer Interface": 「`witnesses`: per-input authorization
metadata required for consumed states.」— base `transfer` の文脈で
`witnesses[i]` が具体的に何を表しうるかの一般規則は書かれていない。
本文全体を通じて `witnesses[i]` に具体的な値が与えられているのは
「KCC20 Borrowed Receive Extension v1」の `BORROWED_RECEIVE = 0xFF` セ
ンチネルのみであり、それ以外の(拡張なしの)通常 transfer において
`witnesses[i]` が何を意味するかの既定値・既定動作(例: 「拡張を使わな
い場合は全て `0x00` を置く」等)が規定されていない。

**KOB の解釈・回避(file:line)**

`kob/core/src/contract/kcc20/transfer.rs:90-95`(module doc):
「`witnesses[]` (kcc-0020 base `transfer` argument) is not threaded
through this wave's bytecode at all: the only currently-specified
semantics for a `witnesses[i]` byte is the Borrowed Receive extension's
`0xFF` sentinel... Adding a pushed-but-never-read `witnesses[]` argument
here would be ceremony, not substance.」KOB は `witnesses[]` を宣言だけ
で意味のない引数として押し込むより、これをそのまま ISSUE として報告す
る方を選んだ。

**提案**

kcc-0020 に、拡張非依存の base `transfer` において `witnesses[i]` が取
るべき既定値(例えば `0x00` = "no extension applies to this consumed
state")を明記し、拡張ごとに `witnesses[i]` の値空間へどう追加の
sentinel 値を割り当てるかの一般規則(レジストリ形式)を追加することを
提案する。ISSUE-5 の `(sig, witness)` 設計論とも合わせて解決するのが自
然である。

### ISSUE-15 — sibling 固定オフセット読みが delegator sigScript の一様 shape を暗黙前提化(HIGH、セキュリティ核心)

これは kcc-0020/kcc-0001 本文の欠陥というより、**KOB の実装設計が仕様の
将来拡張(kcc-0020 自身が定義する Borrowed Receive)と衝突する**という、
実装から逆照射される仕様間整合性の課題である。

**KOB の実装(file:line)**

leader は各 sibling(delegator)入力の `amount`/`extended_state_digest`
を、decode された state 値としてではなく、**sibling の sigScript バイ
ト列上の固定オフセット**から `OpTxInputScriptSigSubstr` で直接読む。
`kob/core/src/contract/kcc20/transfer.rs:209-264`
(`SiblingFieldOffsets`/`sibling_field_offsets`/
`delegator_sigscript_prefix_len`)がこのオフセット計算を行っており、
前提として「あらゆる delegator の sigScript は必ず
`push_data(sig[65B]) || OP_DATA_4 tag || PushMinimal(R)` という一様な
形をしている」ことを固定バイト長の定数(`DELEGATOR_SIG_PUSH_LEN =
1+65`, `DISPATCH_TAG_PUSH_LEN = 1+4`)としてハードコードしている
(transfer.rs:227-236)。この読み取りは leader 側のバイトコード内で
何ら明示的な shape 検証を経ずに行われる — sibling の実際の sigScript
が本当にこの形をしているかどうかは、**sibling 自身の
`transfer_delegator()` 実行がその場で偶然要求する**ことに間接的に依存
しているだけであり、leader 側には対応する明示的な認証ステップがない
(比較: `self_rs` については `dr_input_spk_check` による明示的な P2SH
ハッシュ照合がある — transfer.rs:352-356 — が、sibling の
`amount`/`digest` 読み取りにはこれに相当する認証が存在しない)。

**Borrowed Receive でこの前提が最初に崩れる**

`kob/core/src/contract/kcc20/borrowed_receive.rs:71-83`
(「What a real implementation would need to change」)が、この暗黙
shape 前提が具体的にどう壊れるかを記述している: kcc-0020 の Borrowed
Receive Extension v1 は、`witnesses[i] == BORROWED_RECEIVE` の入力を
「owner の署名協力なしに」successor として再利用することを定義してい
る。これはまさに「delegator は必ず自分自身の65byte署名を sigScript の
固定位置に置く」という前提が成立しない具体例である — borrowed 入力は
定義上、所有者の署名を持たない(kcc-0020: 「The borrowed input is
exempt only from its normal owner authorization」)。この拡張を実際に
配線するには、`transfer.rs` の sibling パスと successor パスを
「shared position index で結合された1つの loop」に再設計する必要があ
り(borrowed_receive.rs:16-31、単なる add-on ではなく core-loop の
redesign だと明記)、現状の固定オフセット方式をそのまま流用すると
witness 駆動でない delegator shape を誤って固定オフセットのまま読も
うとして、意図しないバイト列を `amount`/`digest` として解釈してしまう
リスクがある。

**なぜ HIGH か**

この暗黙の shape 契約は、kcc-0020/kcc-0001 のどこにも明文化されていな
い実装内部の不変条件である。今日の1実装(delegator 自己認可のみ)の下
では sibling 自身の P2SH 実行が間接的にこの shape を強制するため実害
は生じないが、**kcc-0020 自身が正式に定義する唯一の拡張(Borrowed
Receive)を実装しようとした瞬間にこの不変条件が破られる**ことが分かっ
ている。将来、この固定オフセット関数を「再導出せずに」再利用する拡張実
装者がいれば、sibling の sigScript 上の全く無関係なバイト列を
`amount`/`digest` として誤って読み込んでしまう危険がある — これは
「保存則を偽装できる」という意味で covenant のセキュリティ根幹に関わる
クラスの誤りであるため、severity を HIGH とする。

**提案**

kcc-0001/kcc-0020 に、「delegator/witness ごとに異なる invocation
shape が許容される場合、leader はその sibling の consumed state を
固定オフセットではなく、宣言された Program ABI 経由で self-describing
に decode しなければならない(MUST)」という規範を追加することを提案す
る。少なくとも、Borrowed Receive のような「一様 shape が壊れる」拡張を
定義する際は、その拡張の仕様自体に「leader が sibling の shape を安全
に判別する方法」を明記することを求めたい。KOB 側でも、Borrowed Receive
配線時にはこの固定オフセット方式を witness 駆動の self-describing 方
式に置き換える予定である。

### ISSUE-16 — dr 系ヘルパのスタック深度規約が未文書化(MEDIUM)

これも仕様そのものではなく KOB 内部実装の規律の課題だが、
「仕様が要求する template 認証(kcc-0001 §8.5)を安全に実装するのがい
かに罠だらけか」を示す実例として報告する。

**該当箇所(file:line)**

`kob/core/src/contract/kcc20/transfer.rs:443-458` のコード内コメント:

> "NOTE on `dr_output_spk_check`/`dr_suffix_check`'s depth parameters:
> each helper's SECOND (and later) depth argument must already account
> for the stack growth caused by the EARLIER part of that SAME helper
> call... Getting this wrong does not panic at the depth-tracking level
> -- it silently PICKs the wrong stack item... which then fails much
> later and much more confusingly (`OpTxOutputSpk`/arithmetic erroring
> with "NumberTooBig ... 37 bytes"). This was caught only by running the
> engine tests, not by re-deriving the depths on paper."

`crate::contract::dr`(`dr_field_extract`/`dr_input_spk_check`/
`dr_output_spk_check`/`dr_suffix_check`、kcc-0001 §8.5 の template 認証
を実装する共通ヘルパ群、`spot::dca` の D&R ステップでも使用)は、複数
の depth 引数を取るが、後続引数が「そのヘルパ自身が呼び出し前半で積ん
だスタック増分」を織り込み済みであることを要求する — この規約はヘル
パ自体のコード外のどこにも文書化されておらず、KOB 自身、kcc-0020 の
transfer 実装で1回この罠に落ちて、紙上の再導出ではなく実際にエンジンテ
ストを走らせて初めて気づいたことが記録されている。

**提案**

これは kcc-0020/kcc-0001 の仕様修正を求めるものではなく、kcc-0001 §8.5
(template 認証)の**実装ガイド**(non-normative な cookbook / worked
example)として、「複数の連続した stack-depth 依存操作を1つのヘルパに
まとめる際は、各深度引数の基準点(呼び出し前かヘルパ内の中間状態か)を
明示すべき」という実装上のベストプラクティスノートを追加することを提
案する。これは kcc-0001 のカバーする「program ABI」层の外側にある
implementation cookbook 層の話であり、そのような層が公式に存在しないな
らその設置自体を提案したい。

### ISSUE-17 — `int` state payload の非最小性 enforcement がエンジンの `covenants_enabled` フラグに依存(MEDIUM)

**仕様引用**

kcc-0001 §5.3: 「An `int` state payload uses an eight-byte little-endian
signed-magnitude encoding.」— これは固定8byte・非最小(non-minimal)エ
ンコードであるが、`OpAdd`/`OpSub` のような算術 opcode が、Bitcoin系
script engine の伝統である「minimal encoding のみ受理する」ルールの下
でこの非最小8byte値を直接オペランドとして受理できるかどうかは、
kcc-0001 のどこにも触れられていない — これは KCC1 の ABI 仕様ではなく
script engine 側の実装詳細だからである。

**KOB の実測(file:line)**

`kob/core/tests/kcc20_contracts.rs:10-16`(module doc冒頭):

> "the KCC1 `int` state payload (8-byte, non-minimal, signed-magnitude)
> is accepted DIRECTLY by `OpAdd`/`OpSub` only because
> `covenants_enabled` disables minimal-encoding enforcement in this
> engine (`crypto/txscript/src/data_stack.rs`'s `pop_items` uses
> `!self.covenants_enabled` as `enforce_minimal`) -- this is an engine
> behavior kcc-0001 itself never documents, and a script relying on it
> under a hypothetical future engine that DOES enforce minimality here
> would silently break."

つまり `transfer.rs` の保存則チェック(sibling/successor の amount を
`OpAdd`/`OpSub` で直接累算する)が実際に動作するのは、rusty-kaspa の
`TxScriptEngine` が `covenants_enabled = true` のときに限り minimal
encoding enforcement を無効化する、という **kcc-0001 が一切文書化して
いないエンジン側の実装詳細**に依存しているためである。

**提案**

kcc-0001 §5.3 に、「`int` の state payload は非最小(固定8byte)である
必要があり、これを算術演算のオペランドとして直接使用する covenant 実装
は、対象のスクリプトエンジンが covenant コンテキストで minimal encoding
enforcement を無効化する(または非最小8byte値を算術入力として受理す
る)ことに依存する」という旨の、実装者向けの明示的な注記を追加すること
を提案する。これは Kaspa 固有のエンジン実装(rusty-kaspa)を仕様が直接
参照する必要はないが、「この依存が存在すること自体」を読者に警告する価
値がある。

### ISSUE-18 — `identifier_type` の実装は PUBKEY のみ(MEDIUM、ISSUE-4 と表裏)

**仕様引用**

kcc-0020 "## State" が定義する3つの `identifier_type` のうち、KOB が
実際にビットコードを発行できるのは `IDENTIFIER_PUBKEY = 0x00` のみであ
る。

**KOB の実装スコープ(file:line)**

`kob/core/src/contract/kcc20/identifier.rs:69-97`
(`emit_ownership_check`)。`PUBKEY` は `OpCheckSigVerify` で検証する
(既存の `crate::contract::token::TOKEN_UNIT_BODY` と同じ慣行)。
`SCRIPT_HASH`/`COVENANT_ID` は `IdentifierVerificationError::
VerificationRuleUndefined` を返す明示的な未実装であり(83-96行)、これ
は ISSUE-4 で報告した「検証規則が仕様上未定義」の直接の帰結である —
規則が定義されていない以上、実装のしようがない。

ISSUE-4 と本質的に同じ根本原因を指しているが、ISSUE-4 が「仕様側の欠
落」の報告であるのに対し、本 ISSUE は「その欠落の結果として KOB のカ
バレッジが3種類中1種類(33%)に限定されている」という実装側の帰結を、
実装完成度の観点から独立に報告する(kcc-0020 が本来約束する
identifier_type の柔軟性 — pubkey 以外の所有形態のトークンサポート —
が、現状の KOB では利用できないという実務上のギャップ)。

**提案**

ISSUE-4 の解決(SCRIPT_HASH/COVENANT_ID の検証規則の明文化)が本
ISSUE の解決の前提条件である。仕様側の決定が下り次第、KOB 側もこの2種
別の実装を追加する予定である。

### ISSUE-19 — cardinality(consumed input / produced output数)の上限が仕様に存在しない(HIGH、セキュリティ)

**仕様引用**

kcc-0020 "## Transfer Interface" は `next_states`/`signatures`/
`witnesses` をいずれも可変長配列として宣言しており、consumed input・
produced output の個数に一切の上限を課していない。KIP-20 の
"Architectural Patterns" 節(Merge / Many-to-One and Many-to-Many)も
「a single transaction may include multiple isolated authorization
groups」等、cardinality を無制限の一般論として記述するのみで、実装が
遵守すべき具体的な上限や、上限超過時の扱いには触れていない。

一方 Kaspa Script にはループが存在しない。したがって、N-of-N の保存則
検証(consumed 側 amount の合計 == produced 側 amount の合計)を実装す
るには、**あらゆる実装が何らかの固定境界に unroll せざるを得ない**。
これは仕様の欠落ではなく Kaspa Script の制約から来る必然だが、
kcc-0020 はこの必然に対して**実装が満たすべき最低限の規範**(境界を超
えた入力/出力をどう扱うべきか)を一切与えていない。

**KOB の実装(file:line)**

`kob/core/src/contract/kcc20/transfer.rs:130`:
`pub const KCC20_TRANSFER_MAX_N: usize = 4;`(固定 unroll 境界)。

`transfer.rs:336-350`(module doc「Cardinality caps」)がリスクを明記し
ている:

```text
---- Cardinality caps: consumed inputs and produced outputs must fit
the unroll bound. Without this, extra consumed/produced covenant
members beyond MAX_N would silently escape the conservation loops
below. ----
```

KOB はこれを受けて `build_transfer_body`(transfer.rs:336-350)で
`OpCovInputCount <= MAX_N+1` および `OpCovOutputCount <= MAX_N` を
`OP_VERIFY` で明示的に強制し、境界超過分がある場合は **transfer 全体
を reject する**設計にしている。この防御を外す(あるいは実装者が単に
「先頭 MAX_N 件だけをループで処理し、残りは無視する」という素朴な実装
を選ぶ)と、境界外に置かれた consumed input の amount が保存則の合計に
一切算入されないまま produced 側の amount だけが認められてしまい、
**トークンのインフレーション**(存在しないはずの amount が successor
に現れる)を許してしまう。

**なぜ HIGH か**

これは KOB 独自の防御であって、kcc-0020 自体が要求しているものではな
い。つまり「cardinality 上限を明示的に reject する」かどうかは実装者の
裁量に委ねられており、この防御を怠った(あるいは境界チェックの実装を
誤った)独立実装が将来存在すれば、それは kcc-0020 に literally
conformant でありながら token の保存則を破れてしまう。ループ制約から
来る必然的な unroll という実装事情に対して、仕様がその安全な扱い方の
規範を与えていないという構造的なギャップであるため、severity を HIGH
とする。

**提案**

kcc-0020 に「実装は consumed input / produced output の個数に何らかの
上限 `MAX_N` を持たねばならず(MUST)、その上限を超える covenant 入力
/出力が transfer 対象の shared covenant-id context に存在する場合、
transfer 全体を reject しなければならない(MUST)」という規範を明記す
ることを提案する。あわせて `MAX_N` の値自体は実装依存(script size /
mass 制約に応じて選択)でよいことを明示すれば、実装間の互換性要求と
実装の柔軟性の両方を満たせる。

## 4. x402 決済ユースケースからの要求

KOB は KCC-0020 実装と並行して x402(HTTP 402 決済プロトコル)の Kaspa
向けファシリテータ (`kob/x402/`, crate `kob-x402`) を実装しており、
native-KAS scheme (A) と KCC20 covenant scheme (B) の両方を testnet-10 上
で実際に broadcast・確認まで通した実績がある(`kob/x402/X402_STATUS.md`
Phase 3–5)。この実運用の中で、ISSUE-6(Descriptor ワイヤ形式の欠落)が
**理論上の整理不足に留まらず、外部発行トークンを x402 決済で受け取ると
いう具体ユースケースの直接的なブロッカーになっている**ことが分かった。

### 4.1 現状: scheme_kcc20 は KOB 自製 token_unit 専用

x402 の KCC20 scheme (B) 検証ロジック `kob/x402/src/scheme_kcc20.rs`
は、支払い出力が正当かどうかを次の式で判定する
(`scheme_kcc20.rs:101-110`, `:170`):

```rust
fn token_unit_p2sh_script(pubkey: &[u8; 32]) -> Vec<u8> {
    let rs = kob_core::build_token_unit_redeem_script(pubkey);
    ...
}
...
let expected_spk = token_unit_p2sh_script(&recipient_pk);
```

`build_token_unit_redeem_script`(`kob/core/src/contract/token.rs:313-
318`)は次の通り実装されている:

```rust
pub fn build_token_unit_redeem_script(owner_pubkey: &[u8; 32]) -> Vec<u8> {
    let mut rs = Vec::with_capacity(38);
    rs.extend_from_slice(&Kcc20StateHeader::new(*owner_pubkey, identifier_type::PUBKEY, 0).encode_script());
    rs.extend_from_slice(TOKEN_UNIT_BODY);
    rs
}
```

`TOKEN_UNIT_BODY`(`token.rs:277`)は KOB 自身が定めた**コンパイル時定
数**であり、`owner_pubkey` 以外にこの関数をパラメータ化する手段がない
— つまりこの関数が計算できる redeem script は「KOB 自身が発行する
token_unit という**一つの固定テンプレート**」のみである。

x402 の facilitator が「この支払い出力は本当に要求された asset(トーク
ン)の正当な受け取りか」を判定するには、**期待される P2SH アドレス**
(= `Blake2b(redeem_script)` から導かれる scriptPublicKey)を独立に計算
できなければならない。KOB 自身のトークンについてはこれが可能だが(自
分自身のテンプレートを知っているから)、**外部の発行体が発行した
KCC20 準拠トークン**(例えば USDT/USDC 型のステーブルコイン発行体が別
の prefix/suffix・別の extended state layout・別の kcc20_extensions を
持つ covenant で発行したトークン)を受け取ろうとした瞬間、KOB はその発
行体の `prefix`/`suffix`/`extended_state_layout`/`kcc20_extensions` を
**どこからどう取得すればよいか分からない** — これがまさに ISSUE-6 で
報告した Descriptor ワイヤ形式の欠落そのものである。

### 4.2 なぜ descriptor 標準化が x402 の実運用要求になるのか

x402 の decentralized な性質(任意のリソースサーバが任意のトークンを
`asset` として要求できる)を Kaspa 上で実現するには、facilitator が
「見たこともない asset の descriptor を、標準化されたワイヤ形式で取得
し、その場でパースして期待 P2SH アドレスを再構築できる」ことが前提にな
る。この前提が成立しない限り、Kaspa 上の x402 は事実上「facilitator が
あらかじめハードコードして知っているトークンのみ」に制限されてしまい、
ERC-20 を issuer 側の追加協調なしに任意に受け取れる EVM 系 x402 実装
(例: elldeeone/kaspa-x402 が参照する Ethereum 系実装)と比較して決定
的に見劣りする。**「x402 という具体ユースケースが descriptor 標準化を
要求している」**というのが本章の核心的な主張である。

### 4.3 7/24 kaspa-exact-v2 登録との関係

kob-x402 は kaspa-exact-v2 (alpha.8 プロファイル分割: `standard-native`
デフォルト + `additive`)の識別子登録に向けて wire 同期を完了させている
(`kob/x402/src/wire_v2.rs`, `scheme_exact.rs`)。この wire の
`extra` オブジェクトは `assetKind` フィールドを持つが(例:
`wire_v2.rs:621`, `:641` のテストフィクスチャで
`"assetKind": "native"`)、これは現状 **`"native"` 固定の定数**であ
り、KCC20 のような covenant トークン資産を指す `assetKind` の値も、そ
の資産をどう識別するか(descriptor 経由か、covenant_id 直接指定か)
の規約も、上流 (elldeeone/kaspa-x402) 側にもまだ存在しない。つまり
「7/24 の識別子登録は `assetKind=native` について中立に完了できるが、
将来トークン決済へ拡張する際の布石には全くなっていない」— この拡張の
実現には、まさに本報告の ISSUE-6/7(descriptor・ExtensionId のワイヤ形
式)の解決が前提として必要になる。

### 4.4 結論・提案

- kcc-0020 の Descriptor に標準化されたワイヤ形式を与えること
  (ISSUE-6 の提案)を、x402 のような decentralized 決済ユースケースの
  実現条件として改めて強調する。
- descriptor の「公開」経路として、on-chain の何らかの参照可能な場所
  (例えば covenant genesis 時の追加 output やメタデータ)を規定候補と
  して検討することを提案する — オフチェーンの URL レジストリのみに頼
  ると、x402 のような自動化された facilitator が信頼できる形で
  descriptor を検証する手段がなくなる。

## 5. ステーブルコイン発行体機能(issuer-authority / compliance)の不在

### 5.1 仕様本文には freeze/blacklist/pause/seize/issuer/authority/compliance が一切存在しない

kcc-0020.md・kcc-0001.md の全文を対象に、以下の語を grep で確認した:
`freeze`, `blacklist`, `pause`, `seize`, `issuer`, `authority`,
`compliance`。**一致は0件**である。kcc-0020 が正式に定義する拡張は
「KCC20 Borrowed Receive Extension v1」の1つのみであり(kcc-0020.md
"## KCC20 Extensions")、これは受取UTXOの再利用という利便性機能であっ
て、発行体側のコントロール機能とは無関係である。

一方、実在する USD ステーブルコイン(USDT/USDC 型)は例外なく、発行体
による以下のいずれか(多くは両方)を consensus/契約レベルで実装してい
る:
- **凍結(freeze)**: 特定アドレス/UTXOの資産を発行体の一存で一時的に
  移動不能にする。
- **没収(seize)**: 特定アドレス/UTXOの資産を発行体が強制的に別の宛先
  へ移動する(法執行機関の要請、盗難資金の回収などに対応するため)。
- **一時停止(pause)**: コントラクト全体の transfer を一時的に無効化
  する。

これらはいずれも規制対応(sanctions list 対応、盗難資金回収、裁判所命
令対応)のために事実上必須の機能であり、これを持たない資産は現状の
規制環境下でメジャーな発行体からの USD ステーブルコイン発行の実務要件
を満たせない。KCC-0020 はこの種の機能を持つ拡張を一切定義していない。

### 5.2 これは PR #2 の議論でも(別の角度から)示唆されている

kcc-0020 PR #2 の issue コメントで `michaelsutton`(2026-07-15)は、
「open ICC」「virtual state」の一般論を議論する中で、次のように述べて
いる:

> "At the very least, this means that the token descriptor must be able
> to extend the standard transfer call with implementation-specific
> args or witness recipes. But that will typically require asset-
> specific knowledge of how to construct them, **e.g. a blacklist
> exclusion proof + UTXO ref**."

これは「blacklist」という具体的な語で、まさに本章が指摘する compliance
機能の必要性に触れた、kcc-0020 の主要著者自身によるコメントである。た
だしこれは「token descriptor の拡張可能性の一般論の一例」として挙げら
れたものであり、issuer-authority/compliance を KCC20 の**標準拡張**と
して正式に定義する提案には至っていない。本章はこれを一歩進め、具体的
な標準化提案として提出する。

### 5.3 なぜ「1グローバル BL 表」は UTXO モデルでは筋が悪いか

アカウントモデル(EVM 系 ERC-20 の blacklist 実装)であれば「アドレス
→ フラグ」のグローバルマッピングを1つのコントラクトストレージスロット
で持てるが、UTXO モデルでこれを素朴に模倣する(= 1つのグローバル
BL 表 UTXO を毎回参照・更新する)と、その BL 表 UTXO 自体が全ての
transfer のボトルネックになり、**同時に複数の transfer を並行実行でき
なくなる**(concurrency 問題)。この懸念は Kaspa コミュニティでも認識
されており(Shawn の並行性懸念として言及される、KIP-20 の "Split /
One-to-Many" パターンの設計思想とも整合する論点)、Kaspa の BlockDAG
による高い並行性という設計目標そのものと真っ向から矛盾する。

**現実的な解**は per-UTXO の issuer-seize 権限である: 発行体が
「この特定の UTXO を没収する」ための鍵/covenant 権限を持ち、それを行
使する transfer のみがグローバルな状態に触れる(または全く触れない)
設計にすれば、無関係な transfer 同士の並行性は損なわれない。

### 5.4 提案: optional issuer-authority/compliance extension の標準化

kcc-0020 の `kcc20_extensions: ExtensionId[]` の仕組み(ISSUE-7 で報告
した通りワイヤ形式は未定だが、機構自体は存在する)を使って、以下のよ
うな **optional な `kcc20_issuer_authority_v1`(仮称)拡張**を正式に標
準化することを提案する:

- 発行体の identifier(`identifier_type` と同型の 32byte 識別子)を
  descriptor に持たせる。
- `transfer` とは別に(または `transfer` の追加分岐として)
  `issuer_seize(...)` エントリポイントを定義し、発行体の署名 1つで対
  象 UTXO を発行体指定の宛先へ強制移動できるようにする。
- 対象 UTXO が凍結中かどうかを **その UTXO 自身の state から機械判読
  可能にする**(= extended_state に `frozen: bool` 相当のフィールドを
  持たせる、または covenant_id 経由で発行体の凍結リストと連動できる
  ようにする)。global な BL 表を必須にせず、per-UTXO の凍結フラグ +
  発行体による `issuer_seize` の組み合わせで、5.3 で述べた並行性問題を
  回避する設計を推奨する。

descriptor の `kcc20_extensions` にこの拡張の宣言を **必須(MUST)** に
することで、wallet・DEX・エスクロー実装が「この資産は発行体による凍
結・没収を受けうるか」を静的に(オンチェーン実行前に)判定できるように
なる — これは「凍結可能性が機械判読可能である方が DEX/エスクロー/
wallet にとって安全である」という設計原則に基づく。

### 5.5 KOB(DEX)側の副作用: ISSUE-15 との関連

issuer-seize 権限を持つ資産が、KOB のような covenant orderbook DEX の
注文 covenant エスクロー中に没収された場合、注文の settle 処理は
「エスクローされているはずの資産が消えている」状態に直面し、settle 不
能のまま注文が沈黙死する(エラーで気づかれないまま放置される)リスク
がある。これは ISSUE-15 で報告した「leader が sibling の consumed
state を暗黙の shape 前提で読む」設計とも関連する — 発行体の
`issuer_seize` のような、通常の transfer/transfer_delegator とは異なる
shape の covenant 遷移が同一 covenant_id 系列に混在するようになると、
ISSUE-15 で指摘した「一様 shape 前提の脆さ」が issuer-authority 拡張で
も同様に問題化しうる。したがって、issuer-authority/compliance 拡張を
標準化する際は、その拡張が定義する新しい遷移 shape が、他の実装(DEX
等)の「暗黙の shape 前提」を静かに壊さないよう、descriptor 経由で
機械判読可能な shape 記述を伴わせることを強く推奨する。

## 6. kas-smiths.org 投稿用ドラフト (English)

以下は kas-smiths.org スレッド #8(kcc-0020 議論)への投稿を想定した英
語ドラフトである。PR #2 (kaspanet/kccs #2, kcc-0020) / PR #3
(kaspanet/kccs #3, kcc-0001) へのリンクは投稿時に URL を補完する前提と
し、ここでは `[PR #2]`/`[PR #3]` のプレースホルダとしている。全19件の
詳細は本報告の英語版付録として別途共有できる旨を書き添えている。

---

**Subject: Implementation notes from a KCC-0020 conformance pass (KOB)**

Hi all,

We've been implementing KCC-0020 as a conformance pass in KOB (a covenant
orderbook DEX for Kaspa), building the token state, transfer entrypoints,
and descriptor shape directly from the draft text in [PR #2] alongside
KCC-0001 ([PR #3]). Writing an actual implementation surfaced a number of
concrete gaps and interpretation questions, all grounded in specific code
paths rather than abstract concerns. We're sharing them here in case
they're useful input to the review.

We want to flag three that we think matter most:

1. **`State[]` is not encodable under KCC-0001 §5.5/§5.6 as declared.**
   `transfer(State[] next_states, ...)` requires an array of records
   whose every recursively-lowered leaf has a positive fixed payload
   width (§5.5/§5.6), but `State.amount` is an `int`, which as a
   standalone argument uses `PushMinimal` over a variable-width minimal
   ScriptNum (§5.3). We could not find a record-lowering that resolves
   this; the type as declared appears genuinely unencodable. We ended up
   substituting a different design (passing each successor as a whole
   redeem-script blob, authenticated via template-hash checks per
   KCC-0001 §8.5, rather than as a `State[]` argument) — a real
   deviation from the interface as written, not a reading of it.

2. **No cardinality bound on consumed inputs / produced outputs is
   specified**, and Kaspa Script has no loops, so any implementation
   must unroll N-of-N conservation checking to some fixed bound. The
   spec gives no guidance on what an implementation must do about
   inputs/outputs beyond that bound. An implementation that doesn't
   explicitly reject overflow (rather than merely ignoring it) can let
   token amounts outside the unrolled window escape the conservation
   check entirely — i.e. inflate supply while remaining literally
   conformant to the text as written. We'd like to see an explicit MUST
   here regardless of what bound an implementation picks.

3. **A design question about the standard extension mechanism**: Borrowed
   Receive (the one currently-specified extension) lets a consumed state
   be reused as its own successor without the owner's cooperation. Any
   leader-side implementation that reads sibling (delegator) state via
   fixed byte offsets into the sibling's own invocation data — a natural
   optimization we initially reached for — implicitly assumes every
   delegator's invocation has the same shape. Borrowed Receive is the
   first concrete case where that assumption breaks (a borrowed input,
   by definition, carries no owner signature). We think it's worth an
   explicit note in the extension mechanism about how a leader should
   safely distinguish invocation shapes per witness value, rather than
   leaving it to each extension author to rediscover.

A few smaller, more mechanical points that came up along the way:

- `identifier_type = SCRIPT_HASH` / `COVENANT_ID` define how
  `owner_identifier` is interpreted but not what `transfer` must
  actually check to prove ownership against that interpretation — we
  noticed this is already an open thread in the PR #2 review itself.
- The `KCC20Descriptor` has no defined wire format at all (no field
  order, no length-prefixing convention, no `ExtensionId` encoding). Of
  everything KCC-0020 defines, the descriptor is the one piece without
  conformance vectors, and we found this to be an actual blocker: it
  means a facilitator (we hit this building an x402 payment facilitator
  on top of KOB) cannot discover an externally-issued token's template
  bytes to compute its expected P2SH address — it can only validate
  tokens whose exact template it already hard-codes.
- We also noticed that neither KCC-0020 nor KCC-0001 defines any
  issuer-side controls (freeze/seize/pause) at all — the only specified
  extension is Borrowed Receive. Real-world USD-pegged stablecoin
  issuance generally requires some form of this for compliance reasons.
  We'd suggest this is worth standardizing as an optional extension
  (declared, like Borrowed Receive, via `kcc20_extensions`) rather than
  left to ad hoc per-issuer designs, partly so that wallets/DEXes/escrow
  contracts can tell from the descriptor alone whether an asset is
  subject to issuer seizure.

We have a fuller writeup (19 numbered items total, each with the spec
text quoted, the exact code path where we hit the issue, and a concrete
proposal) that we're happy to share in more detail if useful — didn't
want to dump all of it into one post. Thanks to Manyfest, Michael, and
IzioDev for the spec work so far; happy to help test any revisions
against our implementation.

— RossKU / KOB

---
