[<RequireQualifiedAccess>]
module FsSaltpack.Armoring

open System
open System.Numerics
open System.Text
open FSharpPlus

let private blockLength = 32
let private encodedBlockLength = 43
let private wordLength = 15
let private lineLength = 200
let private alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
let private alphabetLength = bigint 62
let private charToInt = function
    | c when c >= '0' && c <= '9' -> int c - 48
    | c when c >= 'A' && c <= 'Z' -> int c - 55
    | c when c >= 'a' && c <= 'z' -> int c - 61
    | _ -> failwith "charToInt error"

type Mode = EncryptedMessage

let internal encode input =
    if Array.isEmpty input then Seq.empty else
    let rec generator x = seq {
        let remainder = x % alphabetLength |> int
        let next = x / alphabetLength
        yield alphabet[Math.Abs(remainder)]
        yield! generator next
    }
    //Extend input by one 0uy to eliminate BigInt negative numbers
    let array = Seq.rev input <|> ([|0uy|] :> seq<_>) |> Seq.toArray
    let length = Array.length array - 1
    let characters =
        Math.Ceiling(8.0 * (float length) / Math.Log(62.0, 2.0)) |> int
    generator (bigint array) |> Seq.take characters |> Seq.rev

let internal decode input =
    let characters =
        Math.Floor(Math.Log(62.0, 2.0) / 8.0 * float (Seq.length input)) |> int
    let value =
        input
        |> Seq.fold
            (fun current character ->
                current * alphabetLength + (charToInt character |> bigint))
            BigInteger.Zero
    let array = value.ToByteArray()
    if array.Length > characters then Seq.take characters array
    elif array.Length < characters then
        (array |> Array.toSeq)
        ++ Seq.init (characters - array.Length) (konst 0uy)
    else array :> seq<byte>
    |> Seq.rev

let armor application mode input =
    let characters =
        Seq.chunkBySize blockLength input
        |>> encode
        >>= id
        |> Seq.chunkBySize wordLength
        |> Seq.chunkBySize lineLength
        |>> intercalate [| ' ' |]
        |> intercalate [| '\n' |]
    let header =
        let prefix =
            match application with
            | None -> "SALTPACK"
            | Some (x : string) -> sprintf "%s SALTPACK" (x.Trim().ToUpper())
        let mode = match mode with | EncryptedMessage -> " ENCRYPTED MESSAGE"
        prefix + mode
    StringBuilder()
        .Append(sprintf "BEGIN %s. " header)
        .Append(characters)
        .Append(sprintf ". END %s." header)
        .ToString()

let dearmor input =
    input
    |> Seq.skipWhile ((<>) '.')
    |> Seq.skip 2
    |> Seq.takeWhile ((<>) '.')
    |> Seq.filter (fun c -> Char.IsLetter c || Char.IsNumber c)
    |> Seq.chunkBySize encodedBlockLength
    |>> decode
    >>= id
