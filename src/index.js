import MonoImage from './MonoImage'

let Mono = {
  GetClass: (imageName, className) => MonoImage.fromName(imageName).getClass(className)
}

const UserMessageManager = Mono.GetClass('Assembly-CSharp', 'UserMessageManager')
UserMessageManager.Instance.UserMessage("huehue", 2, 0, false)

export default Mono

/*
export { default as MonoImage } from './MonoImage'
import MonoImage from './MonoImage'

const UnityEngine = MonoImage.fromName('UnityEngine')
const DebugLogHandler = UnityEngine['UnityEngine.DebugLogHandler']
*/
