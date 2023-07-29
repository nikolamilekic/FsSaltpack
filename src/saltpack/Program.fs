module Saltpack.Program

open System
open System.IO
open Argu
open Milekic.YoLo
open FSharpPlus
open FsSodium

open FsSaltpack

type Argument =
    | [<SubCommand; CliPrefix(CliPrefix.None)>] Encrypt of ParseResults<EncryptArgument>
    | [<SubCommand; CliPrefix(CliPrefix.None)>] Decrypt of ParseResults<DecryptArgument>
    | [<SubCommand; CliPrefix(CliPrefix.None)>] GenerateKeypair
    | Version
    | [<Unique; Inherit>] Input of InputFilePath:string
    | [<Unique; Inherit>] Output of OutputFilePath:string
    interface IArgParserTemplate with
        member this.Usage =
            match this with
            | Encrypt _ -> "Encrypts a file"
            | Decrypt _ -> "Decrypts a file"
            | GenerateKeypair _ -> "Generates a key pair"
            | Input _ -> "Input file path"
            | Output _ -> "Output file path"
            | Version -> "Print version and exit"

and EncryptArgument =
    | [<Unique>] SenderSecretKey of SenderSecretKey:string
    | AnonymousRecipient of RecipientPublicKey:string
    | PublicRecipient of RecipientPublicKey:string
    interface IArgParserTemplate with
        member this.Usage =
            match this with
            | SenderSecretKey _ -> "Sender's secret key. This is not required. If left unspecified the file will be signed using an ephemeral key only."
            | AnonymousRecipient _ -> "A recipient's public key. This recipient will remain anonymous."
            | PublicRecipient _ -> "A recipients public key. This recipient will be public."

and DecryptArgument =
    | [<ExactlyOnce>] RecipientSecretKey of RecipientSecretKey:string
    interface IArgParserTemplate with
        member __.Usage = "Recipient's secret key."

[<EntryPoint>]
let main argv =
    printfn
        "Saltpack encryption utility. Version: %s (%s)"
        Metadata.entryAssemblyInformationalVersion.Value.Value.InformationalVersion
        (DateTimeOffset.Parse(ThisAssembly.Git.CommitDate).ToString("yyyy-MM-dd"))

    try
        let arguments =
            ArgumentParser
                .Create(programName = "saltpack")
                .ParseCommandLine()

        if arguments.TryGetResult Version |> Option.isSome then exit 0

        match arguments.GetSubCommand() with
        | Encrypt args ->
            let input = arguments.PostProcessResult(Input, File.ReadAllBytes)
            let outputPath = arguments.GetResult Output
            let publicKeyParser t =
                Parsing.parseByteArrayFromHexString
                >> PublicKeyEncryption.PublicKey.Import
                >> Result.map (fun x -> t, x)
                >> Result.failOnError "Invalid public key"
            let recipients =
                args.PostProcessResults(
                    AnonymousRecipient, publicKeyParser Encryption.Anonymous)
                ++
                args.PostProcessResults(
                    PublicRecipient, publicKeyParser Encryption.Public)
            let sender =
                args.TryPostProcessResult(
                    SenderSecretKey,
                    Parsing.parseByteArrayFromHexString
                    >> PublicKeyEncryption.SecretKey.Import
                    >> Result.failOnError "Invalid secret key")
                |>> fun x ->
                    x,
                    PublicKeyEncryption.PublicKey.FromSecretKey x
                    |> Result.failOnError "Could not compute public from secret key"
            let unarmored =
                Encryption.encrypt sender recipients input
                |> Result.failOnError "Encryption failed"
            let armored = Armoring.armor None Armoring.EncryptedMessage unarmored
            File.WriteAllText(outputPath, armored)
            printfn "Done."
            0
        | Decrypt args ->
            let armored = arguments.PostProcessResult(Input, File.ReadAllText)
            let outputPath = arguments.GetResult Output
            let secretKey =
                args.PostProcessResult(
                    RecipientSecretKey,
                    Parsing.parseByteArrayFromHexString
                    >> PublicKeyEncryption.SecretKey.Import
                    >> Result.failOnError "Invalid secret key")
            let publicKey =
                    PublicKeyEncryption.PublicKey.FromSecretKey secretKey
                    |> Result.failOnError "Could not compute public from secret key"
            let unarmored = Armoring.dearmor armored |> Seq.toArray
            let (sender, plainText) =
                Encryption.decrypt (secretKey, publicKey) unarmored
                |> Result.failOnError "Decryption failed"

            File.WriteAllBytes(outputPath, plainText)

            match sender with
            | None -> printfn "Done. Sender chose to remain anonymous."
            | Some x -> printfn "Done. Sender was %s." (Parsing.byteArrayToHexString x.Get)

            0
        | GenerateKeypair ->
            let secretKey, publicKey =
                PublicKeyEncryption.SecretKey.Generate()
                |> Result.failOnError "Failed to generate keypair"

            printfn "Secret key: %s" (Parsing.byteArrayToHexString secretKey.Get)
            printfn "Public key: %s" (Parsing.byteArrayToHexString publicKey.Get)
            0
        | _ -> failwith "Unknown sub command"
    with
        | :? ArguParseException as ex ->
            printfn "%s" ex.Message
            int ex.ErrorCode
        | x ->
            printfn "ERROR: %s" x.Message
            -1
