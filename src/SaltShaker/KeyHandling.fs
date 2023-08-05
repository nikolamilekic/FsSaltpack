module SaltShaker.KeyHandling

open System
open Milekic.YoLo
open FSharpPlus
open FSharpPlus.Data
open FsSodium

let publicKeyToTwoWordId (x : PublicKeyEncryption.PublicKey) =
    BaseConverter.toCustomBase 2048 x.Get
    |> Seq.map (fun x -> WordList.wordList[x])
    |> Seq.take 2
    |> curry String.Join " "
