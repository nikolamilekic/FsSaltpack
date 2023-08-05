namespace SaltShaker

open System.Threading

type TypingDelay() =
    let mutable userIsTyping = false
    let mutable userIsStillTyping = false
    member val OnUserStoppedTyping = ignore with get,set
    member this.UserIsTyping() =
        if userIsTyping then
            userIsStillTyping <- true
        else
            userIsTyping <- true
            userIsStillTyping <- true
            let context = SynchronizationContext.Current
            async {
                while userIsStillTyping do
                    userIsStillTyping <- false
                    do! Async.Sleep 300

                userIsTyping <- false
                do! Async.SwitchToContext context
                this.OnUserStoppedTyping()
            } |> Async.Start
