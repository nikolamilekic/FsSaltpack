[<RequireQualifiedAccess>]
module FsSaltpack.Encryption

open System
open System.Text
open System.IO
open System.Threading
open Milekic.YoLo
open FSharpPlus
open FSharpPlus.Data
open FsSodium
open MessagePackParsing
open MessagePackParsing.Parser
open MessagePackSerialization

let private senderSecretBoxNonce =
    Encoding.ASCII.GetBytes("saltpack_sender_key_sbox")
    |> SecretKeyEncryption.Nonce.Import
    |> Result.failOnError "Could not import sender secret box nonce"

let private makeRecipientsNonce index =
    Encoding.ASCII.GetBytes("saltpack_recipsb")
    ++ (index |> uint64 |> toBytesBE)
    |> PublicKeyEncryption.Nonce.Import
    |> Result.failOnError "Could not import recipients nonce"

let private makePayloadNonce index =
    Encoding.ASCII.GetBytes("saltpack_ploadsb")
    ++ (index |> uint64 |> toBytesBE)
    |> SecretKeyEncryption.Nonce.Import
    |> Result.failOnError "Could not import payload nonce"

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
    rawNonce[15] <- rawNonce[15] &&& 0xfeuy
    let! encryptedZerosIdentity =
        let nonce =
            PublicKeyEncryption.Nonce.Import rawNonce
            |> Result.failOnError "Could not import identity nonce"
        uncurry PublicKeyEncryption.encrypt keyPair1 nonce zeros
    rawNonce[15] <- rawNonce[15] ||| 0x01uy
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
            >> Result.failOnError "Could not import authentication key")
}

let private plainTextBufferLength = 1000000 // saltpack spec
let private cipherTextBufferLength = SecretKeyEncryption.getCipherTextLength plainTextBufferLength
let private plainTextBuffer = new ThreadLocal<byte[]>(fun () -> Array.zeroCreate plainTextBufferLength)
let private cipherTextBuffer = new ThreadLocal<byte[]>(fun () -> Array.zeroCreate cipherTextBufferLength)

let encryptTo
    senderKeypair
    (recipients : _ seq)
    (input : Stream)
    (output : Stream) = monad.strict {

    let payloadKey = SecretKeyEncryption.Key.Generate()
    let! ephemeralKeypair = PublicKeyEncryption.SecretKey.Generate()
    let identityKeypair = senderKeypair |> Option.defaultValue ephemeralKeypair
    let! senderSecretBox =
        SecretKeyEncryption.encrypt
            payloadKey
            senderSecretBoxNonce
            (snd identityKeypair).Get
    let recipients = recipients |> Seq.toArray
    let! (encryptedPayloadKeys : (PublicKeyEncryption.PublicKey option * byte array) list) =
        recipients
        |> Seq.mapi (fun index (recipientType, recipientPublicKey) -> monad.strict {
            let nonce = makeRecipientsNonce index
            let! encryptedPayloadKey =
                PublicKeyEncryption.encrypt
                    (fst ephemeralKeypair)
                    recipientPublicKey
                    nonce
                    payloadKey.Get
            match recipientType with
            | Public -> return Some recipientPublicKey, encryptedPayloadKey
            | Anonymous -> return None, encryptedPayloadKey
        })
        |> List.ofSeq
        |> List.sequence

    let recipientsInfo =
        encryptedPayloadKeys
        |> Seq.map (fun (pk, encryptedPayloadKey) ->
            Array [|
                match pk with
                | Some pk -> Str pk.Get
                | None -> Null

                Str encryptedPayloadKey
            |])
        |> Seq.toArray
    let header =
        Array [|
            Str ("saltpack" |> Encoding.UTF8.GetBytes)
            Array [| PositiveFixNum 2uy; PositiveFixNum 0uy |]
            PositiveFixNum 0uy
            Str (snd ephemeralKeypair).Get
            Str senderSecretBox
            Array recipientsInfo
        |]
        |> pack
        |> Seq.toArray

    let! headerHash = HashingSHA512.hash header

    let! (recipientAuthenticationKeys : SecretKeyAuthentication.Key list) =
        recipients
        |> Seq.mapi (fun index (_, recipientKey) ->
            makeAuthenticationKey
                headerHash
                index
                (fst identityKeypair, recipientKey)
                (fst ephemeralKeypair, recipientKey))
        |> List.ofSeq
        |> List.sequence

    let save x =
        let toWrite = pack x |> Seq.toArray
        output.Write(toWrite, 0, Array.length toWrite)

    let read () =
        let readBytes = input.Read(plainTextBuffer.Value, 0, plainTextBufferLength)
        let state = input.Position >= input.Length
        readBytes, state

    save (Binary header)

    let encrypt nonce =
        SecretKeyEncryption.encryptTo payloadKey nonce (PlainText plainTextBuffer.Value) (CipherText cipherTextBuffer.Value)

    let rec iter index = monad.strict {
        let readBytes, doneFlag = read()
        let cipherTextLength = SecretKeyEncryption.getCipherTextLength readBytes
        let nonce = makePayloadNonce index
        do! encrypt nonce readBytes
        let! authenticators = monad.strict {
            let! hashState = HashingSHA512.State.Create()
            let hpl i = HashingSHA512.hashPartWithLength hashState i
            let hp i = hpl i (Array.length i)
            do! hp headerHash
            do! hp nonce.Get
            do! hp <| if doneFlag then [| 1uy |] else [| 0uy |]
            do! hpl cipherTextBuffer.Value cipherTextLength
            let! authenticatorHash = HashingSHA512.completeHash hashState
            return!
                recipientAuthenticationKeys
                |> Seq.map (fun key ->
                    SecretKeyAuthentication.sign key authenticatorHash
                    |>> fun x -> x.Get |> take 32)
                |> List.ofSeq
                |> List.sequence
        }

        let payload = Array [|
            Boolean doneFlag
            Array <| (authenticators |> Seq.map Str |> Seq.toArray)

            if doneFlag
            then Str cipherTextBuffer.Value[..cipherTextLength-1]
            else Str cipherTextBuffer.Value
        |]

        save payload
        if not doneFlag then return! iter (index + 1)
    }

    do! iter 0
}

type DecryptionError =
    | DecryptionSodiumError of SodiumError
    | ParsingError of String
    | UnsupportedSaltpackVersion
    | WrongMode
    | UnexpectedFormat of string
    | NotIntendedRecipient
    | BadAuthenticator

let decryptTo recipientKeyPair (input : Stream) (output : Stream) = monad.strict {
    let! rawHeader =
        run binary input
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
    let! ephemeralPublicKey, senderSecretBox, recipientList =
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

    let write buffer = output.Write(buffer, 0, Array.length buffer)

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
        let mac = authenticators[recipientIndex]
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
            |> List.ofSeq
            |> List.sequence
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

        write plainText
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
