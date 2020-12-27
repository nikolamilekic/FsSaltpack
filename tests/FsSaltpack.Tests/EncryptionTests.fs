module FsSaltpack.Tests.EncryptionTests

open System.Text

open Expecto
open Swensen.Unquote
open Milekic.YoLo
open FSharpPlus

open FsSodium
open FsSaltpack

let alice = PublicKeyEncryption.SecretKey.Generate() |> Result.get
let bob = PublicKeyEncryption.SecretKey.Generate() |> Result.get
let eve = PublicKeyEncryption.SecretKey.Generate() |> Result.get

let Public = Encryption.Public
let Anonymous = Encryption.Anonymous

[<Tests>]
let encryptionTests =
    testList "Encryption" [
        testCase "Encrypting the same text twice does not yield the same cipher text" <| fun _ ->
            let plainText = Seq.init 3 id |>> byte |> toArray
            let cipherText1 =
                Encryption.encrypt (Some alice) [ Public, snd bob ] plainText
            let cipherText2 =
                Encryption.encrypt (Some alice) [ Public, snd bob ] plainText
            cipherText1 <>! cipherText2
            cipherText1 |> Result.isOk =! true
        testList "Rountrip" (
            [ 10; 1000000; 1000001; 1048576; 1048577; 2100000 ]
            |>> fun count -> testCase (count.ToString()) <| fun _ ->
                let plainText = Seq.init count id |>> byte |> toArray
                Encryption.encrypt (Some alice) [ Public, snd bob ] plainText
                |> Result.failOnError "Encryption failed"
                |> Encryption.decrypt bob
                =! Ok (Some <| snd alice, plainText))
        testCase "Alice to herself roundtrip works" <| fun _ ->
            let plainText = Seq.init 5 id |>> byte |> toArray
            Encryption.encrypt (Some alice) [ Public, snd alice ] plainText
            |> Result.failOnError "Encryption failed"
            |> Encryption.decrypt alice
            =! Ok (Some <| snd alice, plainText)
        testCase "Rountrip with anonymous sender works." <| fun _ ->
            let plainText = Seq.init 5 id |>> byte |> toArray
            Encryption.encrypt None [ Public, snd bob ] plainText
            |> Result.failOnError "Encryption failed"
            |> Encryption.decrypt bob
            =! Ok (None, plainText)
        testCase "Rountrip with anonymous recipient works." <| fun _ ->
            let plainText = Seq.init 5 id |>> byte |> toArray
            Encryption.encrypt (Some alice) [ Anonymous, snd bob ] plainText
            |> Result.failOnError "Encryption failed"
            |> Encryption.decrypt bob
            =! Ok (Some <| snd alice, plainText)
        testCase "Rountrip with anonymous recipient and anonymous sender works." <| fun _ ->
            let plainText = Seq.init 5 id |>> byte |> toArray
            Encryption.encrypt None [ Anonymous, snd bob ] plainText
            |> Result.failOnError "Encryption failed"
            |> Encryption.decrypt bob
            =! Ok (None, plainText)
        testCase "Rountrip with multiple recipients works." <| fun _ ->
            let plainText = Seq.init 5 id |>> byte |> toArray
            let recipients = [
                Anonymous, snd bob
                Anonymous, snd alice
                Public, snd eve
            ]
            let encrypted =
                Encryption.encrypt (Some alice) recipients plainText
                |> Result.failOnError "Encryption failed"

            test <@ Encryption.decrypt alice encrypted = Ok (Some (snd alice), plainText) @>
            test <@ Encryption.decrypt bob encrypted = Ok (Some (snd alice), plainText) @>
            test <@ Encryption.decrypt eve encrypted = Ok (Some (snd alice), plainText) @>
        testCase "Decrypt fails with modified cipher text" <| fun _ ->
            let plainText = Seq.init 5 id |>> byte |> toArray
            Encryption.encrypt (Some alice) [ Public, snd bob ] plainText
            |> Result.failOnError "Encryption failed"
            |> fun c ->
                c.[0] <- if c.[0] = 0uy then 1uy else 0uy
                Encryption.decrypt bob c
            |> fun x -> test <@ Result.isError x @>
        testCase "Decrypt fails with wrong key" <| fun _ ->
            let plainText = Seq.init 5 id |>> byte |> toArray
            Encryption.encrypt (Some alice) [ Public, snd bob ] plainText
            |> Result.failOnError "Encryption failed"
            |> fun c ->
                c.[0] <- if c.[0] = 0uy then 1uy else 0uy
                Encryption.decrypt eve c
            |> fun x -> test <@ Result.isError x @>
        testCase "Known plain text test" <| fun _ ->
            let expected = "This is a test" |> Encoding.UTF8.GetBytes
            let input = Seq.toArray <| Armoring.dearmor "BEGIN SALTPACK ENCRYPTED MESSAGE. kiNOlZz3hicHWTZ DqaSd6GGaC7Vhka YjCOz2VrAaM2ZWQ kO0NOE3URkYqnLO hOQj3t2tGaYXfyN y1la51fa0QKsWU2 fKadGtDcAkcRVVB MIFkxPsSOavIetK 58c5cUIRJE7TDvw ievu5CQfcF2qQRD XLpaaAY12TiswQh zXZVsP7NDpHOCkW D6bIU9USnoZYAZy RmrsogMs05dv5Yz XpZasDXhouYIyWy FbqawGbE2vOzMdv lH0uERUy8MTDTVJ X6Yph4AeFcgNltq aKVwdm76n9cgZzU RcOjYjOV7Es6BYm b8nPsLLlbvo6Ea4 WLWa9smlaYmt1En ksuFTFPverPH32L XFhWiKiMu7pgtDz KBlhJmd481VRFab Z7Z3Ma3NqZP9Xcc iU8idcr2UbnWUcy I40FjldUikaBmW2 CjxOxrzZnkRU2vI 2eAi5DJbn0N1XEs XSsh0iDzmC1vIlJ AGMgfKqJYh06dPp oMVKJQVhmiXgWJa NVJCvxjtMM59ZAt Ab. END SALTPACK ENCRYPTED MESSAGE."
            let expectedSender =
                PublicKeyEncryption.PublicKey.Import
                <| Parsing.parseByteArrayFromHexString
                    "3b089f8289fd517741b98c1b06fc78cef4e996d8b06f0299b3c6086c3b17a653"
                |> Result.failOnError "Could not import expectedSender"
            let parseRecipient (s, p) =
                PublicKeyEncryption.SecretKey.Import
                <| Parsing.parseByteArrayFromHexString s
                |> Result.failOnError "Could not import recipient secretKey"
                ,
                PublicKeyEncryption.PublicKey.Import
                <| Parsing.parseByteArrayFromHexString p
                |> Result.failOnError "Could not import recipient public key"
            let recipient1 = parseRecipient ("85d81e579b05f067af448016461c70713c56b41f7d5c7684d0a166dab57404ce", "d4a939923fb9cb9e78155a74450d68020c89aec561eef1316bdd89ec0fe76709")
            let recipient2 = parseRecipient ("971da7faf898224d82df202bd67f524bc986cb1398dbe41924f64c027f309032", "fb5f7072ce989591f335368dcd2b5973eb2e87cbf06e12bac2de94df9525190f")
            Encryption.decrypt recipient1 input =! Ok (Some expectedSender, expected)
            Encryption.decrypt recipient2 input =! Ok (Some expectedSender, expected)
    ]
