import { MonoImage, MonoClass } from './api'

const assemblyCSharp = MonoImage.loaded('Assembly-CSharp')
const UserMessageManager = MonoClass.fromName(assemblyCSharp, '', 'UserMessageManager')
console.log(UserMessageManager)
