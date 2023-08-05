module SaltShaker.KeyView

open System
open Avalonia.Layout
open Avalonia.FuncUI.DSL
open Avalonia.Controls

let make (state : KeyViewState) dispatch = StackPanel.create [
    Panel.classes [ "main-panel" ]
    Panel.children [
        StackPanel.create [
            StackPanel.orientation Orientation.Horizontal
            StackPanel.children [
                Button.create [
                    Button.content "Generate"
                    Button.onClick (fun _ -> dispatch GenerateKey)
                ]
                Button.create [
                    Button.content "Unload"
                    Button.onClick (fun _ -> dispatch UnloadKeys)
                    Button.isEnabled state.CanUnload
                ]
                Button.create [
                    Button.content "Load"
                    Button.onClick (fun _ -> dispatch LoadKeys)
                    Button.isEnabled state.CanEnter
                ]
            ]
        ]
        TextBlock.create [ TextBlock.text "Secret Key:" ]
        TextBox.create [
            TextBox.text state.SecretKey
            TextBox.errors (if String.IsNullOrEmpty state.SecretKeyError then  [] else [ state.SecretKeyError ])
            TextBox.isReadOnly (not state.CanChangeSecretKey)
            TextBox.onTextChanged (UpdateSecretKey >> dispatch)
        ]
        StackPanel.create [
            Control.isVisible (not state.CanChangeSecretKey)
            StackPanel.children [
                TextBlock.create [ TextBlock.text "Public Key:" ]
                TextBox.create [
                    TextBox.text state.PublicKey
                    TextBox.isReadOnly true
                ]
            ]
        ]
    ]
]
