import { MonoMetaTableEnum } from 'core/constants'
import { createNativeFunction } from 'core/native'
import { MonoBase } from './MonoBase'
import { MonoTableInfo } from './MonoTableInfo'

export const mono_image_loaded = createNativeFunction('mono_image_loaded', 'pointer', ['pointer'])
export const mono_image_get_filename = createNativeFunction('mono_image_get_filename', 'pointer', ['pointer'])
export const mono_image_get_name = createNativeFunction('mono_image_get_name', 'pointer', ['pointer'])
export const mono_image_get_table_info = createNativeFunction('mono_image_get_table_info', 'pointer', ['pointer', 'int'])

/*
std::list<MonoClass*> GetAssemblyClassList(MonoImage * image)
{
   std::list<MonoClass*> class_list;

   const MonoTableInfo* table_info = mono_image_get_table_info(image, MONO_TABLE_TYPEDEF);

   int rows = mono_table_info_get_rows(table_info);

   for (int i = 0; i < rows; i++)
   {
       MonoClass* _class = nullptr;
       uint32_t cols[MONO_TYPEDEF_SIZE];
       mono_metadata_decode_row(table_info, i, cols, MONO_TYPEDEF_SIZE);
       const char* name = mono_metadata_string_heap(image, cols[MONO_TYPEDEF_NAME]);
       const char* name_space = mono_metadata_string_heap(image, cols[MONO_TYPEDEF_NAMESPACE]);
       _class = mono_class_from_name(image, name_space, name);
       class_list.push_back(_class);
   }
   return class_list
}
*/

/**
 * Mono doc: http://docs.go-mono.com/?link=xhtml%3adeploy%2fmono-api-image.html
 */

export class MonoImage extends MonoBase {
  get fileName(): string {
    return mono_image_get_filename(this.$address).readUtf8String()
  }

  get name(): string {
    return mono_image_get_name(this.$address).readUtf8String()
  }

  getTableInfo(tableId: MonoMetaTableEnum): MonoTableInfo {
    const address = mono_image_get_table_info(this.$address, tableId)
    return MonoTableInfo.fromAddress(address)
  }

  /**
   * Static methods
   */
  static loaded(assemblyName: string): MonoImage {
    const address: NativePointer = mono_image_loaded(Memory.allocUtf8String(assemblyName))
    return MonoImage.fromAddress(address)
  }
}
