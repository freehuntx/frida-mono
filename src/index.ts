/* eslint-disable @typescript-eslint/no-unused-vars */
export * as api from 'api'
export * as core from 'core'

/**
 * Below code is for testing purpose
 */

import { MonoImage } from 'api'

const assemblyCSharp = MonoImage.loaded('Assembly-CSharp')
const a = assemblyCSharp.getResource(0)
console.log(JSON.stringify(a))

/*import { MonoImage, MonoClass } from 'api'
import { MonoMetaTableEnum } from 'core/constants'

const assemblyCSharp = MonoImage.loaded('Assembly-CSharp')

const UserMessageManager = MonoClass.fromName(assemblyCSharp, '', 'UserMessageManager')
console.log(UserMessageManager.arrayElementSize)*/

/*const tableInfo = assemblyCSharp.getTableInfo(MonoMetaTableEnum.MONO_TABLE_TYPEDEF)
console.log(tableInfo.rows)*/

/*
const UserMessageManager = MonoClass.fromName(assemblyCSharp, '', 'UserMessageManager')
console.log(UserMessageManager)
*/
