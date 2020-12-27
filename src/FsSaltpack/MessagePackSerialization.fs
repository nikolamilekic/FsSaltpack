module FsSaltpack.MessagePackSerialization

open System

type Pack =
    | Null
    | Str of byte[]
    | Binary of byte[]
    | PositiveFixNum of byte
    | Boolean of bool
    | Array of Pack[]

let twoByteLength x =
    int16 x |> BitConverter.GetBytes |> Array.rev
let fourByteLength (x : int32) = BitConverter.GetBytes x |> Array.rev

let rec pack x = seq {
    match x with
    | Null -> yield 0xc0uy
    | Array x ->
        let length = Array.length x
        if length < 16 then
            yield byte <| length + 144
        elif length < 65536 then
            yield 0xdcuy
            yield! twoByteLength length
        else
            yield 0xdduy
            yield! fourByteLength length
        for sub in x do yield! pack sub
    | Str x ->
        let length = Array.length x
        if length < 32 then
            yield byte <| length + 160
        elif length < 256 then
            yield 0xd9uy
            yield byte length
        elif length < 65536 then
            yield 0xdauy
            yield! twoByteLength length
        else
            yield 0xdbuy
            yield! fourByteLength length
        yield! x
    | Binary x ->
        let length = Array.length x
        if length < 256 then
            yield 0xc4uy
            yield byte length
        elif length < 65536 then
            yield 0xc5uy
            yield! twoByteLength length
        else
            yield 0xc6uy
            yield! fourByteLength length
        yield! x
    | PositiveFixNum x -> yield x
    | Boolean x -> if x then yield 0xc3uy else yield 0xc2uy
}

