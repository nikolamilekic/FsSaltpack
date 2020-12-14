[<RequireQualifiedAccess>]
module FsSaltpack.Encryption

open System
open System.Text
open System.IO
open Milekic.YoLo
open FSharpPlus
open MsgPack
open FsSodium

let private senderSecretBoxNonce =
    Encoding.ASCII.GetBytes("saltpack_sender_key_sbox")
    |> SecretKeyEncryption.Nonce.Import
    |> Result.failOnError ("Could not import sender secret box nonce")

let private makeRecipientsNonce endianness index =
    Encoding.ASCII.GetBytes("saltpack_recipsb")
    ++ (index |> uint64 |> endianness)
    |> PublicKeyEncryption.Nonce.Import
    |> Result.failOnError ("Could not import recipients nonce")

let private makePayloadNonce endianness index =
    Encoding.ASCII.GetBytes("saltpack_ploadsb")
    ++ (index |> uint64 |> endianness)
    |> SecretKeyEncryption.Nonce.Import
    |> Result.failOnError ("Could not import payload nonce")

type RecipientType = Public | Anonymous

let private zeros : byte[] = Array.zeroCreate 32
let private makeAuthenticationKey
    endianness
    (headerHash : byte[])
    index
    keyPair1
    keyPair2 = monad.strict {
    let rawNonce =
        (headerHash |> take 16)
        ++ (index |> uint64 |> endianness)
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
    endianness
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
            let nonce = makeRecipientsNonce endianness index
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
                endianness
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
        let nonce = makePayloadNonce endianness index
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
    | ReadError of Exception
    | WriteError of IOException
    | UnsupportedSaltpackVersion
    | WrongMode
    | UnexpectedFormat of string
    | NotIntendedRecipient
    | BadAuthenticator

let decryptTo recipientKeyPair (input : Stream) (output : Stream) = monad.strict {
    try
        let rawHeader = Unpacking.UnpackBinary(input)
        let! headerHash =
            HashingSHA512.hash rawHeader
            |> Result.mapError DecryptionSodiumError
        let header = Unpacking.UnpackArray(rawHeader)

        let format = header.Value.[0].AsString()
        if format <> "saltpack" then return! Error <| UnexpectedFormat "Wrong magic string" else

        let versionInfo = header.Value.[1].AsList()

        let majorVersion = versionInfo.[0].AsByte()
        if majorVersion <> 2uy then return! Error UnsupportedSaltpackVersion else

        let minorVersion = versionInfo.[1].AsByte()
        if minorVersion <> 0uy then return! Error UnsupportedSaltpackVersion else

        let mode = header.Value.[2].AsByte()
        if mode <> 0uy then return! Error WrongMode else

        let! ephemeralPublicKey =
            header.Value.[3].AsBinary()
            |> PublicKeyEncryption.PublicKey.Import
            |> Result.mapError (konst <| UnexpectedFormat "Ephemeral public key length is wrong")
        let senderSecretBox = header.Value.[4].AsBinary()
        let recipientList =
            header.Value.[5].AsList()
            |> Seq.mapi (fun index (o : MessagePackObject) ->
                let t = o.AsList()
                let key =
                    if t.[0].IsNil then None else
                        t.[0].AsBinary()
                        |> PublicKeyEncryption.PublicKey.Import
                        |> Some
                index, key, t.[1].AsBinary())
            |> Seq.toList

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
                let nonceBE = makeRecipientsNonce toBytesBE index
                PublicKeyEncryption.decryptWithSharedSecret
                    sharedSecret nonceBE box
                |> Result.bindError (fun _ ->
                    let nonceLE = makeRecipientsNonce toBytes index
                    PublicKeyEncryption.decryptWithSharedSecret
                        sharedSecret nonceLE box)
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

        let! authenticationKeyBE =
            makeAuthenticationKey
                toBytesBE
                headerHash
                recipientIndex
                (fst recipientKeyPair, senderPublicKey)
                (fst recipientKeyPair, ephemeralPublicKey)
            |> Result.mapError DecryptionSodiumError

        let! authenticationKeyLE =
            makeAuthenticationKey
                toBytes
                headerHash
                recipientIndex
                (fst recipientKeyPair, senderPublicKey)
                (fst recipientKeyPair, ephemeralPublicKey)
            |> Result.mapError DecryptionSodiumError

        let write buffer =
            try output.Write(buffer, 0, Array.length buffer) |> Ok
            with | :? IOException as exn -> Error <| WriteError exn

        let rec iter index = monad.strict {
            let packet = Unpacking.UnpackArray(input)
            let finalFlag = packet.[0].AsBoolean()
            let mac = packet.[1].AsList().[recipientIndex].AsBinary()
            let payload = packet.[2].AsBinary()
            let nonceBE = makePayloadNonce toBytesBE index
            let nonceLE = makePayloadNonce toBytes index

            let! hashStateBE =
                HashingSHA512.State.Create()
                |> Result.mapError DecryptionSodiumError
            let! hashStateLE =
                HashingSHA512.State.Create()
                |> Result.mapError DecryptionSodiumError

            do!
                seq {
                    headerHash
                    nonceBE.Get
                    if finalFlag then [| 1uy |] else [| 0uy |]
                    payload
                }
                |>> (HashingSHA512.hashPart hashStateBE
                    >> Result.mapError DecryptionSodiumError)
                |> Result.sequence
                >>= fun _ ->
                    HashingSHA512.completeHash hashStateBE
                    |> Result.mapError DecryptionSodiumError
                >>= fun hash ->
                    SecretKeyAuthentication.sign authenticationKeyBE hash
                    |> bimap DecryptionSodiumError (fun x -> x.Get |> take 32)
                >>= fun actualMac ->
                    if actualMac = mac then Ok () else Error BadAuthenticator
                |> Result.bindError (fun x ->
                    seq {
                        headerHash
                        nonceLE.Get
                        if finalFlag then [| 1uy |] else [| 0uy |]
                        payload
                    }
                    |>> (HashingSHA512.hashPart hashStateLE
                        >> Result.mapError DecryptionSodiumError)
                    |> Result.sequence
                    >>= fun _ ->
                        HashingSHA512.completeHash hashStateLE
                        |> Result.mapError DecryptionSodiumError
                    >>= fun hash ->
                        SecretKeyAuthentication.sign authenticationKeyLE hash
                        |> bimap DecryptionSodiumError (fun x -> x.Get |> take 32)
                    >>= fun actualMac ->
                        if actualMac = mac then Ok () else Error BadAuthenticator)

            let! plainText =
                SecretKeyEncryption.decrypt payloadKey nonceBE payload
                |> Result.bindError (fun _ ->
                    SecretKeyEncryption.decrypt payloadKey nonceLE payload)
                |> Result.mapError DecryptionSodiumError

            do! write plainText

            if not finalFlag then return! iter (index + 1) else return ()
        }

        do! iter 0

        return
            if senderPublicKey = ephemeralPublicKey
            then None
            else Some senderPublicKey
    with exn ->
        return! Error <| ReadError exn
}

let encrypt endianness senderKeypair recipients (input : byte[]) =
    let input = new MemoryStream(input)
    let output = new MemoryStream()
    encryptTo endianness senderKeypair recipients input output |>> output.ToArray

let decrypt recipientKeyPair (input : byte[]) =
    let input = new MemoryStream(input)
    let output = new MemoryStream()
    decryptTo recipientKeyPair input output |>> fun pk -> pk, output.ToArray()
