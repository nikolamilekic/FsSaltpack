module FsSaltpack.MessagePackParsing

open System.IO
open System.Text
open FSharpPlus.Operators

module Parser =
    type Parser<'a, 'e> =
        private Parser of (Stream -> Result<'a, 'e>)

    let run (Parser p) stream = p stream
    let runWithArray p (array : byte[]) = run p (new MemoryStream(array))

    let map f (Parser e) = e >> Result.map f |> Parser
    let mapError f (Parser e) = e >> Result.mapError f |> Parser
    let bind f (Parser e) =
        Parser <| fun stream ->
            match e stream with
            | Error e -> Error e
            | Ok result1 ->
                let (Parser inner) = f result1
                inner stream
    let liftResult x = Parser (fun _ -> x)
    let result x = Parser (fun _ -> Ok x)
    let fail x = Parser (fun _ -> Error x)
    let private (>>=) e f = bind f e
    let private (|>>) e f = map f e
    let traverse f (source : _ seq) =
        Parser <| fun stream ->
            use enumerator = source.GetEnumerator()
            let rec inner state =
                if enumerator.MoveNext() = false
                then Ok (state |> Seq.rev |> Seq.toArray)
                else
                    let (Parser p) = f enumerator.Current
                    match p stream with
                    | Error e -> Error e
                    | Ok x -> inner (x::state)
            inner []
    let sequence source = traverse id source
    let multiple count a = Seq.replicate count a |> sequence
    let specific p v =
        run p
        >> function
            | Ok x -> if x = v then Ok x else Error <| sprintf "Expecting %A but received %A" v x
            | Error e -> Error <| sprintf "Expecting %A but received ERROR %A" v e
        |> Parser
    let pipe2 p1 p2 = p1 >>= fun r1 ->  p2 >>= fun r2 -> result (r1, r2)
    let pipe3 p1 p2 p3 f =
        p1 >>= fun r1 ->
        p2 >>= fun r2 ->
        p3 >>= fun r3 ->result <| f r1 r2 r3
    let pipe6 p1 p2 p3 p4 p5 p6 f =
        p1 >>= fun r1 ->
        p2 >>= fun r2 ->
        p3 >>= fun r3 ->
        p4 >>= fun r4 ->
        p5 >>= fun r5 ->
        p6 >>= fun r6 -> result <| f r1 r2 r3 r4 r5 r6
    let (.>>.) = pipe2
    let (.>>) p1 p2 = p1 .>>. p2 |>> fst
    let (>>.) p1 p2 = p1 .>>. p2 |>> snd
    let orElse (Parser p1) (Parser p2) =
        Parser <| fun stream ->
            let initialPosition = stream.Position
            match p1 stream with
            | Ok x -> Ok x
            | Error _ ->
                stream.Position <- initialPosition
                p2 stream
    let (<|>) = orElse

    type Parser<'a, 'e> with
        static member Return(x) = result x
        static member Map(e, f) = map f e
        static member (>>=)(e, f) = bind f e

    let pbyte =
        Parser <| fun stream ->
            try
                let result = stream.ReadByte()
                if result = -1
                then Error "Unexpected end of stream"
                else Ok result
            with _ -> Error "Error occurred while reading stream"
    let byteArray buffer count =
        Parser <| fun stream ->
            try
                let readBytes = stream.Read(buffer, 0, count)
                if readBytes = count
                then Ok buffer
                else Error "Unexpected end of stream."
            with _ -> Error "Error occurred while reading stream"

open Parser

let private twoByteLength = pbyte .>>. pbyte |>> fun (l, r) -> l * 256 + r
let private fourByteLength : Parser<int, _> =
    multiple 4 pbyte
    |>> fun bytes ->
        bytes.[0] * 16777216
        + bytes.[1] * 65536
        + bytes.[2] * 256
        + bytes.[3]
let binary =
    let fixStr =
        pbyte
        |> mapError ignore >>= fun x ->
            let length = x - 160
            if length < 0 || length > 31
            then fail ()
            else result length
    fixStr
    <|> (specific pbyte 0xd9 >>. pbyte)
    <|> (specific pbyte 0xda >>. twoByteLength)
    <|> (specific pbyte 0xdb >>. fourByteLength)
    <|> (specific pbyte 0xc4 >>. pbyte)
    <|> (specific pbyte 0xc5 >>. twoByteLength)
    <|> (specific pbyte 0xc6 >>. fourByteLength)
    >>= fun length ->
        let buffer = Array.zeroCreate length
        byteArray buffer length
let stringPack = binary |>> Encoding.UTF8.GetString
let arrayHeader =
    let fixArray =
        pbyte
        |> mapError ignore >>= fun x ->
            let length = x - 144
            if length < 0 || length > 15
            then fail ()
            else result length
    fixArray
    <|> (specific pbyte 0xdc >>. twoByteLength)
    <|> (specific pbyte 0xdd >>. fourByteLength)
let positiveFixNum =
    pbyte >>= fun r ->
        if r > 127
        then fail "Positive FixNum can only store numbers up to 127"
        else result r
let nullPack = specific pbyte 0xc0 |>> ignore
let boolPack =
    specific pbyte 0xc2 |>> konst false <|> (specific pbyte 0xc3 |>> konst true)
