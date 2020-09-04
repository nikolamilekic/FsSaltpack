module FsSaltpack.Tests.EncryptionTests

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
    ]
