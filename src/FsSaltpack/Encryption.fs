[<RequireQualifiedAccess>]
module FsSaltpack.Encryption

open System
open System.Text
open System.IO
open Milekic.YoLo
open FSharpPlus
open MsgPack
open FsSodium
open MessagePackParsing
open MessagePackParsing.Parser

let private senderSecretBoxNonce =
    Encoding.ASCII.GetBytes("saltpack_sender_key_sbox")
    |> SecretKeyEncryption.Nonce.Import
    |> Result.failOnError ("Could not import sender secret box nonce")

let private makeRecipientsNonce index =
    Encoding.ASCII.GetBytes("saltpack_recipsb")
    ++ (index |> uint64 |> toBytesBE)
    |> PublicKeyEncryption.Nonce.Import
    |> Result.failOnError ("Could not import recipients nonce")

let private makePayloadNonce index =
    Encoding.ASCII.GetBytes("saltpack_ploadsb")
    ++ (index |> uint64 |> toBytesBE)
    |> SecretKeyEncryption.Nonce.Import
    |> Result.failOnError ("Could not import payload nonce")

type RecipientType = Public | Anonymous

let private zeros : byte[] = Array.zeroCreate 32
let private makeAuthenticationKey
    (headerHash : byte[])
    index
    keyPair1
    keyPair2 = monad.strict {
    let rawNonce =
        (headerHash |> take 16)
        ++ (index |> uint64 |> toBytesBE)
    rawNonce.[15] <- rawNonce.[15] &&& 0xfeuy
    let! encryptedZerosIdentity =
        let nonce =
            PublicKeyEncryption.Nonce.Import rawNonce
            |> Result.failOnError "Could not import identity nonce"
        uncurry PublicKeyEncryption.encrypt keyPair1 nonce zeros
    rawNonce.[15] <- rawNonce.[15] ||| 0x01uy
    let! encryptedZerosEphemeral =
        let nonce =
            PublicKeyEncryption.Nonce.Import rawNonce
            |> Result.failOnError "Could not import ephemeral nonce"
        uncurry PublicKeyEncryption.encrypt keyPair2 nonce zeros
    return!
        (encryptedZerosIdentity |> rev |> take 32 |> rev)
        ++ (encryptedZerosEphemeral |> rev |> take 32 |> rev)
        |> HashingSHA512.hash
        |>> (take 32
            >> SecretKeyAuthentication.Key.Import
            >> Result.failOnError ("Could not import authentication key"))
}

type EncryptionError =
    | EncryptionSodiumError of SodiumError
    | ReadError of IOException
    | WriteError of Exception
let encryptTo
    senderKeypair
    (recipients : _ seq)
    (input : Stream)
    (output : Stream) = monad.strict {

    let payloadKey = SecretKeyEncryption.Key.Generate()
    let! ephemeralKeypair =
        PublicKeyEncryption.SecretKey.Generate()
        |> Result.mapError EncryptionSodiumError
    let identityKeypair = senderKeypair |> Option.defaultValue ephemeralKeypair
    let! senderSecretBox =
        SecretKeyEncryption.encrypt
            payloadKey
            senderSecretBoxNonce
            (snd identityKeypair).Get
        |> Result.mapError EncryptionSodiumError
    let recipients = recipients |> Seq.toArray
    let! encryptedPayloadKeys =
        recipients
        |> Seq.mapi (fun index (recipientType, recipientPublicKey) -> monad.strict {
            let nonce = makeRecipientsNonce index
            let! encryptedPayloadKey =
                PublicKeyEncryption.encrypt
                    (fst ephemeralKeypair)
                    recipientPublicKey
                    nonce
                    payloadKey.Get
                |> Result.mapError EncryptionSodiumError
            match recipientType with
            | Public -> return Some recipientPublicKey, encryptedPayloadKey
            | Anonymous -> return None, encryptedPayloadKey
        })
        |> Result.sequence

    let recipientsCount = encryptedPayloadKeys |> List.length
    let header =
        use headerStream = new MemoryStream()
        let headerPacker = Packer.Create(headerStream)
        headerPacker
            .PackArrayHeader(6)
            .PackString("saltpack")
            .PackArray([| 2uy; 0uy |])
            .Pack(0uy)
            .PackBinary((snd ephemeralKeypair).Get)
            .PackBinary(senderSecretBox)
        |> ignore

        headerPacker.PackArrayHeader recipientsCount |> ignore

        encryptedPayloadKeys
        |> Seq.iter (fun (pk, encryptedPayloadKey) ->
            headerPacker.PackArrayHeader 2 |> ignore
            match pk with
            | Some pk -> headerPacker.PackBinary pk.Get
            | None -> headerPacker.PackNull()
            |> ignore
            headerPacker.PackBinary encryptedPayloadKey |> ignore)

        headerStream.ToArray()
    let! headerHash =
        HashingSHA512.hash header |> Result.mapError EncryptionSodiumError

    let! recipientAuthenticationKeys =
        recipients
        |> Seq.mapi (fun index (_, recipientKey) ->
            makeAuthenticationKey
                headerHash
                index
                (fst identityKeypair, recipientKey)
                (fst ephemeralKeypair, recipientKey)
            |> Result.mapError EncryptionSodiumError)
        |> Result.sequence

    let run =
        let outputPacker = Packer.Create(output, PackerCompatibilityOptions.None)
        (fun (f : Packer -> Packer) ->
            try f outputPacker |> ignore; Ok ()
            with exn -> Error <| WriteError exn)

    let inputBuffer : byte[] = Array.zeroCreate 1000000
    let read () =
        try
            let readBytes = input.Read(inputBuffer, 0, 1000000)
            let state = input.Position >= input.Length
            Ok <| (readBytes, state)
        with | :? IOException as exn -> Error <| ReadError exn

    do! run (fun packer -> packer.PackBinary header)

    let buffersFactory = SecretKeyEncryption.makeBuffersFactory()
    let buffers = buffersFactory.FromPlainText(inputBuffer)
    let encrypt nonce =
        SecretKeyEncryption.encryptTo payloadKey nonce buffers
        >> Result.mapError EncryptionSodiumError

    let rec iter index = monad.strict {
        let! (readBytes, doneFlag) = read()
        let nonce = makePayloadNonce index
        do! encrypt nonce readBytes
        let! authenticators = monad.strict {
            let! hashState =
                HashingSHA512.State.Create()
                |> Result.mapError EncryptionSodiumError
            let hpl i =
                HashingSHA512.hashPartWithLength hashState i
                >> Result.mapError EncryptionSodiumError
            let hp i = hpl i (Array.length i)
            do! hp headerHash
            do! hp nonce.Get
            do! hp <| if doneFlag then [| 1uy |] else [| 0uy |]
            let cipherTextLength = buffersFactory.GetCipherTextLength readBytes
            do! hpl buffers.CipherText cipherTextLength
            let! authenticatorHash =
                HashingSHA512.completeHash hashState
                |> Result.mapError EncryptionSodiumError
            return!
                recipientAuthenticationKeys
                |> Seq.map (fun key ->
                    SecretKeyAuthentication.sign key authenticatorHash
                    |> bimap EncryptionSodiumError (fun x -> x.Get |> take 32))
                |> Result.sequence
        }

        do! run <| fun packer ->
            packer
                .PackArrayHeader(3)
                .Pack(doneFlag)
                .PackArray(authenticators)

        if doneFlag
        then
            let cipherTextLength = buffersFactory.GetCipherTextLength(readBytes)
            return! run <| fun packer ->
                packer.PackBinary(buffers.CipherText.[..cipherTextLength-1])
        else
            do! run <| fun packer -> packer.PackBinary(buffers.CipherText)
            return! iter (index + 1)
    }

    do! iter 0
    do! run <| fun packer -> packer.Flush(); packer.Dispose(); packer
}

type DecryptionError =
    | DecryptionSodiumError of SodiumError
    | ParsingError of String
    | WriteError of IOException
    | UnsupportedSaltpackVersion
    | WrongMode
    | UnexpectedFormat of string
    | NotIntendedRecipient
    | BadAuthenticator

let decryptTo recipientKeyPair (input : Stream) (output : Stream) = monad.strict {
    let! rawHeader =
        Parser.run binary input
        |> Result.mapError (konst <| ParsingError "Invalid outer header format")
    let! headerHash =
        HashingSHA512.hash rawHeader
        |> Result.mapError DecryptionSodiumError

    let magicStringParser =
        specific stringPack "saltpack"
        |> mapError (konst <| UnexpectedFormat "Wrong magic string")
    let versionInfoParser =
        specific arrayHeader 2
        |> mapError (konst <| ParsingError "Invalid version array")
        >>.
            ((specific positiveFixNum 2
            >>. specific positiveFixNum 0)
            |> mapError (konst UnsupportedSaltpackVersion))
    let modeParser =
        specific positiveFixNum 0 |> mapError (konst WrongMode)
    let ephemeralPublicKeyParser =
        binary |> mapError (konst <| ParsingError "Invalid ephemeral key format.")
        >>=
            (PublicKeyEncryption.PublicKey.Import
            >> Result.mapError (konst <| UnexpectedFormat "Ephemeral public key length is wrong")
            >> liftResult)
    let senderSecretBoxParser =
        binary |> mapError (konst <| ParsingError "Invalid sender secret box format")
    let recipientListParser =
        let recipientKey =
            nullPack |>> konst None
            <|> (binary |>> (PublicKeyEncryption.PublicKey.Import >> Some))
        let recipient =
            specific arrayHeader 2 |> mapError (konst <| ParsingError "Invalid recipient info format")
            >>. (recipientKey .>>. binary |> mapError (konst <| ParsingError "Invalid recipient key format"))
        arrayHeader
        |> mapError (konst <| ParsingError "Invalid recipient array")
        >>= fun length -> multiple length recipient
        |>> (Seq.mapi (fun index (r, kb) -> index, r, kb) >> Seq.toList)
    let headerParser =
        specific arrayHeader 6 |> mapError (konst <| ParsingError "Invalid header format")
        >>. magicStringParser
        >>. versionInfoParser
        >>. modeParser
        >>. pipe3 ephemeralPublicKeyParser senderSecretBoxParser recipientListParser tuple3
    let! (ephemeralPublicKey, senderSecretBox, recipientList) =
        runWithArray headerParser rawHeader

    let! sharedSecret =
        PublicKeyEncryption.SharedSecret.Precompute
            (fst recipientKeyPair)
            ephemeralPublicKey
        |> Result.mapError DecryptionSodiumError

    let! rawPayloadKey, recipientIndex =
        recipientList
        |> Seq.tryFind (fun (_, r, _) ->
            r = Some (Ok (snd recipientKeyPair)))
        |>> Seq.singleton
        |> Option.defaultWith (fun _ ->
            recipientList
            |> Seq.filter (fun (_, b, _) -> b = None))
        |>> fun (index, _, box) ->
            let nonce = makeRecipientsNonce index
            PublicKeyEncryption.decryptWithSharedSecret
                sharedSecret nonce box
            |> Option.ofResult
            |>> fun x -> x, index
        |> Seq.tryPick id
        |> option Ok (Error NotIntendedRecipient)

    let! payloadKey =
        rawPayloadKey
        |> SecretKeyEncryption.Key.Import
        |> Result.mapError (konst <| UnexpectedFormat "Payload key length is wrong")

    let! senderPublicKey =
        SecretKeyEncryption.decrypt
            payloadKey senderSecretBoxNonce senderSecretBox
        |> Result.mapError DecryptionSodiumError
        >>= (PublicKeyEncryption.PublicKey.Import
            >> Result.mapError (konst <| UnexpectedFormat "Sender public key length is wrong"))

    let! authenticationKey =
        makeAuthenticationKey
            headerHash
            recipientIndex
            (fst recipientKeyPair, senderPublicKey)
            (fst recipientKeyPair, ephemeralPublicKey)
        |> Result.mapError DecryptionSodiumError

    let write buffer =
        try output.Write(buffer, 0, Array.length buffer) |> Ok
        with | :? IOException as exn -> Error <| WriteError exn

    let payloadParser =
        let authenticators =
            specific arrayHeader (List.length recipientList)
            >>= fun l -> multiple l binary
        specific arrayHeader 3
        >>. pipe3 boolPack authenticators binary tuple3
        |> mapError (konst <| ParsingError "Wrong payload format")

    let rec iter index = monad.strict {
        let! (finalFlag, authenticators : byte[][], payload : byte[]) =
            run payloadParser input
        let mac = authenticators.[recipientIndex]
        let nonce = makePayloadNonce index

        let! hashState =
            HashingSHA512.State.Create()
            |> Result.mapError DecryptionSodiumError

        do!
            seq {
                headerHash
                nonce.Get
                if finalFlag then [| 1uy |] else [| 0uy |]
                payload
            }
            |>> (HashingSHA512.hashPart hashState
                >> Result.mapError DecryptionSodiumError)
            |> Result.sequence
            >>= fun _ ->
                HashingSHA512.completeHash hashState
                |> Result.mapError DecryptionSodiumError
            >>= fun hash ->
                SecretKeyAuthentication.sign authenticationKey hash
                |> bimap DecryptionSodiumError (fun x -> x.Get |> take 32)
            >>= fun actualMac ->
                if actualMac = mac then Ok () else Error BadAuthenticator

        let! plainText =
            SecretKeyEncryption.decrypt payloadKey nonce payload
            |> Result.mapError DecryptionSodiumError

        do! write plainText

        if not finalFlag then return! iter (index + 1) else return ()
    }

    do! iter 0

    return
        if senderPublicKey = ephemeralPublicKey
        then None
        else Some senderPublicKey
}

let encrypt senderKeypair recipients (input : byte[]) =
    let input = new MemoryStream(input)
    let output = new MemoryStream()
    encryptTo senderKeypair recipients input output |>> output.ToArray

let decrypt recipientKeyPair (input : byte[]) =
    let input = new MemoryStream(input)
    let output = new MemoryStream()
    decryptTo recipientKeyPair input output |>> fun pk -> pk, output.ToArray()
