module SaltShaker.EncryptView

open System
open System.Threading
open Avalonia.Layout
open FSharp.Core
open FSharp.Control.Reactive
open FSharpPlus
open Milekic.FsBech32
open Avalonia.Interactivity
open Avalonia.FuncUI.DSL
open Avalonia.Controls

let make (state : EncryptViewState) dispatch = Grid.create [
    Grid.rowDefinitions "Auto * Auto 110"
    Panel.classes [ "main-panel" ]
    Panel.children [
        StackPanel.create [
            Grid.row 0
            Panel.children [
                TextBlock.create [ TextBlock.text "Recipients:" ]
                ListBox.create [
                    ListBox.dataItems (state.Recipients |>> fun r ->
                        let shorthand = KeyHandling.publicKeyToTwoWordId r
                        (Bech32.encode KeyViewEventProcessor.publicKeyPrefix r.Get |> Result.get) + $" ({shorthand})")
                ]
                TextBlock.create [ TextBlock.text "Add Recipient:" ]
                TextBox.create [
                    TextBox.text state.AddRecipientInput
                    TextBox.errors (
                        if String.IsNullOrEmpty state.RecipientInputError
                        then [] else [ state.RecipientInputError ] )
                    TextBox.onTextChanged (UpdateAddRecipientInput >> dispatch)
                ]
                StackPanel.create [
                    StackPanel.orientation Orientation.Horizontal
                    Panel.children [
                        Button.create [
                            Button.content "Add Recipient"
                            Button.onClick (fun _ -> dispatch AddRecipient)
                        ]
                        Button.create [
                            Button.content "Clear Recipients"
                            Button.onClick (fun _ -> dispatch ClearRecipients)
                        ]
                    ]
                ]
                TextBlock.create [ TextBlock.text "Plain Text:" ]
            ]
        ]
        TextBox.create [
            Grid.row 1
            yield! EncryptDecryptCommon.bigTextBoxProperties
            TextBox.text state.PlainText
            TextBox.init (fun (tb : TextBox) ->
                let handler (args : RoutedEventArgs) =
                    dispatch (UpdatePlainText (args.Source :?> TextBox).Text)
                    dispatch Encrypt

                tb.TextChanged
                |> Observable.throttle (TimeSpan.FromMilliseconds 300.)
                |> Observable.observeOnContext SynchronizationContext.Current
                |> Observable.subscribe handler
                |> ignore

                tb.LostFocus.Add handler)
        ]
        TextBlock.create [ Grid.row 2; TextBlock.text "Cipher Text:" ]
        TextBox.create [
            Grid.row 3
            yield! EncryptDecryptCommon.bigTextBoxProperties
            TextBox.text state.CipherText
            TextBox.isReadOnly true
        ]
    ]
]
