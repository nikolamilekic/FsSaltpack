module FsSaltpack.Tests.ArmoringTests

open Expecto
open Swensen.Unquote
open Milekic.YoLo
open FSharpPlus

open FsSaltpack

[<Tests>]
let armoringTests =
    testList "Armoring" [
        testProperty "Encode/decode roundtrip works as expected" <| fun x ->
            Armoring.encode x |> Armoring.decode |> Seq.toArray =! x
        testProperty "Armor/dearmor roundtrip works as expected" <| fun x ->
            Armoring.armor None Armoring.Mode.EncryptedMessage x
            |> Armoring.dearmor |> Seq.toArray =! x
    ]
