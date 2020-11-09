import { MonoImage, MonoClass } from './api'
import { MonoMetaTableEnum } from './core/constants'

const assemblyCSharp = MonoImage.loaded('Assembly-CSharp')

const UserMessageManager = MonoClass.fromName(assemblyCSharp, '', 'UserMessageManager')
console.log(UserMessageManager.arrayElementSize)

/*const tableInfo = assemblyCSharp.getTableInfo(MonoMetaTableEnum.MONO_TABLE_TYPEDEF)
console.log(tableInfo.rows)*/

/*
const UserMessageManager = MonoClass.fromName(assemblyCSharp, '', 'UserMessageManager')
console.log(UserMessageManager)
*/
