(function (global, factory) {
    typeof exports === 'object' && typeof module !== 'undefined' ? factory(exports) :
    typeof define === 'function' && define.amd ? define(['exports'], factory) :
    (global = typeof globalThis !== 'undefined' ? globalThis : global || self, factory(global.FridaMono = {}));
}(this, (function (exports) { 'use strict';

    var MonoMetaTableEnum;
    (function (MonoMetaTableEnum) {
        MonoMetaTableEnum[MonoMetaTableEnum["MONO_TABLE_MODULE"] = 0] = "MONO_TABLE_MODULE";
        MonoMetaTableEnum[MonoMetaTableEnum["MONO_TABLE_TYPEREF"] = 1] = "MONO_TABLE_TYPEREF";
        MonoMetaTableEnum[MonoMetaTableEnum["MONO_TABLE_TYPEDEF"] = 2] = "MONO_TABLE_TYPEDEF";
        MonoMetaTableEnum[MonoMetaTableEnum["MONO_TABLE_FIELD_POINTER"] = 3] = "MONO_TABLE_FIELD_POINTER";
        MonoMetaTableEnum[MonoMetaTableEnum["MONO_TABLE_FIELD"] = 4] = "MONO_TABLE_FIELD";
        MonoMetaTableEnum[MonoMetaTableEnum["MONO_TABLE_METHOD_POINTER"] = 5] = "MONO_TABLE_METHOD_POINTER";
        MonoMetaTableEnum[MonoMetaTableEnum["MONO_TABLE_METHOD"] = 6] = "MONO_TABLE_METHOD";
        MonoMetaTableEnum[MonoMetaTableEnum["MONO_TABLE_PARAM_POINTER"] = 7] = "MONO_TABLE_PARAM_POINTER";
        MonoMetaTableEnum[MonoMetaTableEnum["MONO_TABLE_PARAM"] = 8] = "MONO_TABLE_PARAM";
        MonoMetaTableEnum[MonoMetaTableEnum["MONO_TABLE_INTERFACEIMPL"] = 9] = "MONO_TABLE_INTERFACEIMPL";
        MonoMetaTableEnum[MonoMetaTableEnum["MONO_TABLE_MEMBERREF"] = 10] = "MONO_TABLE_MEMBERREF"; /* 0xa */
        MonoMetaTableEnum[MonoMetaTableEnum["MONO_TABLE_CONSTANT"] = 11] = "MONO_TABLE_CONSTANT";
        MonoMetaTableEnum[MonoMetaTableEnum["MONO_TABLE_CUSTOMATTRIBUTE"] = 12] = "MONO_TABLE_CUSTOMATTRIBUTE";
        MonoMetaTableEnum[MonoMetaTableEnum["MONO_TABLE_FIELDMARSHAL"] = 13] = "MONO_TABLE_FIELDMARSHAL";
        MonoMetaTableEnum[MonoMetaTableEnum["MONO_TABLE_DECLSECURITY"] = 14] = "MONO_TABLE_DECLSECURITY";
        MonoMetaTableEnum[MonoMetaTableEnum["MONO_TABLE_CLASSLAYOUT"] = 15] = "MONO_TABLE_CLASSLAYOUT";
        MonoMetaTableEnum[MonoMetaTableEnum["MONO_TABLE_FIELDLAYOUT"] = 16] = "MONO_TABLE_FIELDLAYOUT"; /* 0x10 */
        MonoMetaTableEnum[MonoMetaTableEnum["MONO_TABLE_STANDALONESIG"] = 17] = "MONO_TABLE_STANDALONESIG";
        MonoMetaTableEnum[MonoMetaTableEnum["MONO_TABLE_EVENTMAP"] = 18] = "MONO_TABLE_EVENTMAP";
        MonoMetaTableEnum[MonoMetaTableEnum["MONO_TABLE_EVENT_POINTER"] = 19] = "MONO_TABLE_EVENT_POINTER";
        MonoMetaTableEnum[MonoMetaTableEnum["MONO_TABLE_EVENT"] = 20] = "MONO_TABLE_EVENT";
        MonoMetaTableEnum[MonoMetaTableEnum["MONO_TABLE_PROPERTYMAP"] = 21] = "MONO_TABLE_PROPERTYMAP";
        MonoMetaTableEnum[MonoMetaTableEnum["MONO_TABLE_PROPERTY_POINTER"] = 22] = "MONO_TABLE_PROPERTY_POINTER";
        MonoMetaTableEnum[MonoMetaTableEnum["MONO_TABLE_PROPERTY"] = 23] = "MONO_TABLE_PROPERTY";
        MonoMetaTableEnum[MonoMetaTableEnum["MONO_TABLE_METHODSEMANTICS"] = 24] = "MONO_TABLE_METHODSEMANTICS";
        MonoMetaTableEnum[MonoMetaTableEnum["MONO_TABLE_METHODIMPL"] = 25] = "MONO_TABLE_METHODIMPL";
        MonoMetaTableEnum[MonoMetaTableEnum["MONO_TABLE_MODULEREFa"] = 26] = "MONO_TABLE_MODULEREFa"; /* 0x1a */
        MonoMetaTableEnum[MonoMetaTableEnum["MONO_TABLE_TYPESPECb"] = 27] = "MONO_TABLE_TYPESPECb";
        MonoMetaTableEnum[MonoMetaTableEnum["MONO_TABLE_IMPLMAPc"] = 28] = "MONO_TABLE_IMPLMAPc";
        MonoMetaTableEnum[MonoMetaTableEnum["MONO_TABLE_FIELDRVAd"] = 29] = "MONO_TABLE_FIELDRVAd";
        MonoMetaTableEnum[MonoMetaTableEnum["MONO_TABLE_UNUSED6e"] = 30] = "MONO_TABLE_UNUSED6e";
        MonoMetaTableEnum[MonoMetaTableEnum["MONO_TABLE_UNUSED7f"] = 31] = "MONO_TABLE_UNUSED7f";
        MonoMetaTableEnum[MonoMetaTableEnum["MONO_TABLE_ASSEMBLY"] = 32] = "MONO_TABLE_ASSEMBLY"; /* 0x20 */
        MonoMetaTableEnum[MonoMetaTableEnum["MONO_TABLE_ASSEMBLYPROCESSOR"] = 33] = "MONO_TABLE_ASSEMBLYPROCESSOR";
        MonoMetaTableEnum[MonoMetaTableEnum["MONO_TABLE_ASSEMBLYOS"] = 34] = "MONO_TABLE_ASSEMBLYOS";
        MonoMetaTableEnum[MonoMetaTableEnum["MONO_TABLE_ASSEMBLYREF"] = 35] = "MONO_TABLE_ASSEMBLYREF";
        MonoMetaTableEnum[MonoMetaTableEnum["MONO_TABLE_ASSEMBLYREFPROCESSOR"] = 36] = "MONO_TABLE_ASSEMBLYREFPROCESSOR";
        MonoMetaTableEnum[MonoMetaTableEnum["MONO_TABLE_ASSEMBLYREFOS"] = 37] = "MONO_TABLE_ASSEMBLYREFOS";
        MonoMetaTableEnum[MonoMetaTableEnum["MONO_TABLE_FILE"] = 38] = "MONO_TABLE_FILE";
        MonoMetaTableEnum[MonoMetaTableEnum["MONO_TABLE_EXPORTEDTYPE"] = 39] = "MONO_TABLE_EXPORTEDTYPE";
        MonoMetaTableEnum[MonoMetaTableEnum["MONO_TABLE_MANIFESTRESOURCE"] = 40] = "MONO_TABLE_MANIFESTRESOURCE";
        MonoMetaTableEnum[MonoMetaTableEnum["MONO_TABLE_NESTEDCLASS"] = 41] = "MONO_TABLE_NESTEDCLASS";
        MonoMetaTableEnum[MonoMetaTableEnum["MONO_TABLE_GENERICPARAMa"] = 42] = "MONO_TABLE_GENERICPARAMa"; /* 0x2a */
        MonoMetaTableEnum[MonoMetaTableEnum["MONO_TABLE_METHODSPECb"] = 43] = "MONO_TABLE_METHODSPECb";
        MonoMetaTableEnum[MonoMetaTableEnum["MONO_TABLE_GENERICPARAMCONSTRAINTc"] = 44] = "MONO_TABLE_GENERICPARAMCONSTRAINTc";
        //#define MONO_TABLE_LAST MONO_TABLE_GENERICPARAMCONSTRAINT
        //#define MONO_TABLE_NUM (MONO_TABLE_LAST + 1)
    })(MonoMetaTableEnum || (MonoMetaTableEnum = {}));
    var MonoImageOpenStatus;
    (function (MonoImageOpenStatus) {
        MonoImageOpenStatus[MonoImageOpenStatus["MONO_IMAGE_OK"] = 0] = "MONO_IMAGE_OK";
        MonoImageOpenStatus[MonoImageOpenStatus["MONO_IMAGE_ERROR_ERRNO"] = 1] = "MONO_IMAGE_ERROR_ERRNO";
        MonoImageOpenStatus[MonoImageOpenStatus["MONO_IMAGE_MISSING_ASSEMBLYREF"] = 2] = "MONO_IMAGE_MISSING_ASSEMBLYREF";
        MonoImageOpenStatus[MonoImageOpenStatus["MONO_IMAGE_IMAGE_INVALID"] = 3] = "MONO_IMAGE_IMAGE_INVALID";
    })(MonoImageOpenStatus || (MonoImageOpenStatus = {}));

    const KNOWN_RUNTIMES = ['mono.dll', 'libmonosgen-2.0.so'];
    const KNOWN_EXPORTS = ['mono_thread_attach'];
    const KNOWN_STRINGS = ["'%s' in MONO_PATH doesn't exist or has wrong permissions"];
    /**
     * To work with mono we need the mono module thats loaded in the current process.
     * This function tries to find it using 3 methods.
     * - Find by module name
     * - Find by export function names
     * - Find by strings in memory
     */
    function findMonoModule() {
        for (const runtime of KNOWN_RUNTIMES) {
            const module = Process.findModuleByName(runtime);
            if (module)
                return module;
        }
        for (const exportName of KNOWN_EXPORTS) {
            const exportFunction = Module.findExportByName(null, exportName);
            if (exportFunction)
                return Process.findModuleByAddress(exportFunction);
        }
        const allModules = Process.enumerateModules();
        for (const module of allModules) {
            for (const string of KNOWN_STRINGS) {
                const pattern = string
                    .split('')
                    .map((e) => ('0' + e.charCodeAt(0).toString(16)).slice(-2))
                    .join(' ');
                const matches = Memory.scanSync(module.base, module.size, pattern);
                if (matches.length > 0) {
                    return Process.findModuleByAddress(matches[0].address);
                }
            }
        }
        throw new Error('Failed finding the mono module!');
    }
    const module = findMonoModule();

    class ExNativeFunction extends NativeFunction {
        constructor(address, retType = 'void', argTypes = [], abiOrOptions = 'default') {
            super(address, retType, argTypes, abiOrOptions);
            this.abi = 'default';
            this.address = address;
            this.retType = retType;
            this.argTypes = argTypes;
            if (typeof abiOrOptions === 'string') {
                this.abi = abiOrOptions;
            }
            else if (typeof abiOrOptions === 'object') {
                this.abi = abiOrOptions.abi || 'default';
                this.options = abiOrOptions;
            }
        }
        nativeCallback(callback) {
            return new NativeCallback(callback, this.retType, this.argTypes, this.abi);
        }
        intercept(callbacksOrProbe, data) {
            return Interceptor.attach(this.address, callbacksOrProbe, data);
        }
        replace(replacement, data) {
            return Interceptor.replace(this.address, replacement, data);
        }
        toString() {
            return `ExNativeFunction[address=${this.address}, retType=${this.retType}, argTypes=[${this.argTypes}], abi=${this.abi}]`;
        }
    }

    function createNativeFunction(name, retType, argTypes, abiOrOptions = 'default') {
        const address = Module.findExportByName(module.name, name);
        if (!address) {
            console.warn('Warning! Native mono export not found! Expected export: ' + name);
            return (() => {
                throw new Error('Native mono function not found! (' + name + ')');
            });
        }
        return new ExNativeFunction(address, retType, argTypes, abiOrOptions);
    }

    var index = /*#__PURE__*/Object.freeze({
        __proto__: null,
        get MonoMetaTableEnum () { return MonoMetaTableEnum; },
        get MonoImageOpenStatus () { return MonoImageOpenStatus; },
        module: module,
        createNativeFunction: createNativeFunction
    });

    class MonoBase {
        constructor(address) {
            this.$address = NULL;
            this.$address = address;
        }
        static fromAddress(address) {
            if (address.isNull())
                return null;
            const addressNumber = address.toInt32();
            if (this.cache[addressNumber] === undefined) {
                this.cache[addressNumber] = new this(address);
            }
            return this.cache[addressNumber];
        }
    }
    MonoBase.cache = {};

    const mono_table_info_get_rows = createNativeFunction('mono_table_info_get_rows', 'int', ['pointer']);
    class MonoTableInfo extends MonoBase {
        get rowSize() {
            return mono_table_info_get_rows(this.$address);
        }
    }

    const mono_image_loaded = createNativeFunction('mono_image_loaded', 'pointer', ['pointer']);
    const mono_image_get_filename = createNativeFunction('mono_image_get_filename', 'pointer', ['pointer']);
    const mono_image_get_name = createNativeFunction('mono_image_get_name', 'pointer', ['pointer']);
    const mono_image_get_table_info = createNativeFunction('mono_image_get_table_info', 'pointer', ['pointer', 'int']);
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
    class MonoImage extends MonoBase {
        get fileName() {
            return mono_image_get_filename(this.$address).readUtf8String();
        }
        get name() {
            return mono_image_get_name(this.$address).readUtf8String();
        }
        getTableInfo(tableId) {
            const address = mono_image_get_table_info(this.$address, tableId);
            return MonoTableInfo.fromAddress(address);
        }
        /**
         * Static methods
         */
        static loaded(assemblyName) {
            const address = mono_image_loaded(Memory.allocUtf8String(assemblyName));
            return MonoImage.fromAddress(address);
        }
    }

    const mono_assembly_name_new = createNativeFunction('mono_assembly_name_new', 'pointer', ['pointer']);
    const mono_assembly_close = createNativeFunction('mono_assembly_close', 'void', ['pointer']);
    //export const mono_assembly_get_object = createNativeFunction('mono_assembly_get_object', 'pointer', ['pointer', 'pointer'])
    const mono_assembly_load = createNativeFunction('mono_assembly_load', 'pointer', ['pointer', 'pointer', 'pointer']);
    const mono_assembly_load_full = createNativeFunction('mono_assembly_load_full', 'pointer', ['pointer', 'pointer', 'pointer', 'bool']);
    const mono_assembly_loaded = createNativeFunction('mono_assembly_loaded', 'pointer', ['pointer']);
    const mono_assembly_load_from = createNativeFunction('mono_assembly_load_from', 'pointer', ['pointer', 'pointer', 'pointer']);
    const mono_assembly_load_from_full = createNativeFunction('mono_assembly_load_from_full', 'pointer', ['pointer', 'pointer', 'pointer', 'bool']);
    const mono_assembly_load_with_partial_name = createNativeFunction('mono_assembly_load_with_partial_name', 'pointer', ['pointer', 'pointer']);
    const mono_assembly_open = createNativeFunction('mono_assembly_open', 'pointer', ['pointer', 'pointer']);
    const mono_assembly_open_full = createNativeFunction('mono_assembly_open_full', 'pointer', ['pointer', 'pointer', 'bool']);
    const mono_set_assemblies_path = createNativeFunction('mono_set_assemblies_path', 'void', ['pointer']);
    //export const mono_set_rootdir = createNativeFunction('mono_set_rootdir', 'void', ['void'])
    //export const mono_assembly_fill_assembly_name = createNativeFunction('mono_assembly_fill_assembly_name', 'bool', ['pointer', 'pointer'])
    const mono_assembly_foreach = createNativeFunction('mono_assembly_foreach', 'void', ['pointer', 'pointer']);
    const mono_assembly_get_image = createNativeFunction('mono_assembly_get_image', 'pointer', ['pointer']);
    class MonoAssembly extends MonoBase {
        /**
         * @returns {MonoImage}
         */
        get image() {
            const address = mono_assembly_get_image(this.$address);
            return MonoImage.fromAddress(address);
        }
        /**
         * This method releases a reference to the assembly. The assembly is only released when all the outstanding references to it are released.
         * @returns {void}
         */
        close() {
            mono_assembly_close(this.$address);
        }
        /**
         * Loads the assembly referenced by aname, if the value of basedir is not NULL, it attempts to load the assembly from that directory before probing the standard locations.
         * @param {string} name - A MonoAssemblyName with the assembly name to load.
         * @param {string} basedir - A directory to look up the assembly at.
         * @returns {MonoAssembly} The assembly referenced by name loaded.
         */
        static load(name, basedir) {
            const monoAssemblyName = mono_assembly_name_new(Memory.allocUtf8String(name));
            const status = Memory.alloc(Process.pointerSize);
            const address = mono_assembly_load(monoAssemblyName, Memory.allocUtf8String(basedir), status);
            if (address.isNull()) {
                throw new Error('Failed loading MonoAssembly! Error: ' + MonoImageOpenStatus[status.readInt()]);
            }
            return MonoAssembly.fromAddress(address);
        }
        /**
         * Loads the assembly referenced by aname, if the value of basedir is not NULL, it attempts to load the assembly from that directory before probing the standard locations.
         * If the assembly is being opened in reflection-only mode (refonly set to TRUE) then no assembly binding takes place.
         * @param {string} name - A MonoAssemblyName with the assembly name to load.
         * @param {string} basedir - A directory to look up the assembly at.
         * @param {boolean} refOnly - Whether this assembly is being opened in "reflection-only" mode.
         * @returns {MonoAssembly} The assembly referenced by aname loaded.
         */
        static loadFull(name, basedir, refOnly) {
            const monoAssemblyName = mono_assembly_name_new(Memory.allocUtf8String(name));
            const status = Memory.alloc(Process.pointerSize);
            const address = mono_assembly_load_full(monoAssemblyName, Memory.allocUtf8String(basedir), status, refOnly);
            if (address.isNull()) {
                throw new Error('Failed loading MonoAssembly! Error: ' + MonoImageOpenStatus[status.readInt()]);
            }
            return MonoAssembly.fromAddress(address);
        }
        /**
         * This is used to determine if the specified assembly has been loaded.
         * @param {string} name - An assembly to look for.
         * @returns {MonoAssembly} NULL If the given aname assembly has not been loaded, or a MonoAssembly that matches the MonoAssemblyName specified.
         */
        static loaded(name) {
            const monoAssemblyName = mono_assembly_name_new(Memory.allocUtf8String(name));
            const address = mono_assembly_loaded(monoAssemblyName);
            return MonoAssembly.fromAddress(address);
        }
        /**
         * If the provided image has an assembly reference, it will process the given image as an assembly with the given name.
         * Most likely you want to use the MonoAssembly.loadFull method instead.
         * This is equivalent to calling MonoAssembly.loadFromFull with the refonly parameter set to FALSE.
         * @param {MonoImage} image - Image to load the assembly from.
         * @param {string} name - Assembly name to associate with the assembly.
         * @returns {MonoAssembly}
         */
        static loadFrom(image, name) {
            const status = Memory.alloc(Process.pointerSize);
            const address = mono_assembly_load_from(image.$address, Memory.allocUtf8String(name), status);
            if (address.isNull()) {
                throw new Error('Failed loading MonoAssembly! Error: ' + MonoImageOpenStatus[status.readInt()]);
            }
            return MonoAssembly.fromAddress(address);
        }
        /**
         * If the provided image has an assembly reference, it will process the given image as an assembly with the given name.
         * Most likely you want to use the MonoAssembly.loadFullMethod instead.
         * @param {MonoImage} image - Image to load the assembly from.
         * @param {string} name - Assembly name to associate with the assembly.
         * @param {boolean} refOnly - Whether this assembly is being opened in "reflection-only" mode.
         * @returns {MonoAssembly}
         */
        static loadFromFull(image, name, refOnly) {
            const status = Memory.alloc(Process.pointerSize);
            const address = mono_assembly_load_from_full(image.$address, Memory.allocUtf8String(name), status, refOnly);
            if (address.isNull()) {
                throw new Error('Failed loading MonoAssembly! Error: ' + MonoImageOpenStatus[status.readInt()]);
            }
            return MonoAssembly.fromAddress(address);
        }
        /**
         * Loads a Mono Assembly from a name. The name is parsed using MonoAssembly.nameParse, so it might contain a qualified type name, version, culture and token.
         * This will load the assembly from the file whose name is derived from the assembly name by appending the .dll extension.
         * The assembly is loaded from either one of the extra Global Assembly Caches specified by the extra GAC paths (specified by the MONO_GAC_PREFIX environment variable) or if that fails from the GAC
         * @param {string} name - An assembly name that is then parsed by MonoAssembly.nameParse
         * @returns {MonoAssembly}
         */
        static loadWithPartialName(name) {
            const status = Memory.alloc(Process.pointerSize);
            const address = mono_assembly_load_with_partial_name(Memory.allocUtf8String(name), status);
            if (address.isNull()) {
                throw new Error('Failed loading MonoAssembly! Error: ' + MonoImageOpenStatus[status.readInt()]);
            }
            return MonoAssembly.fromAddress(address);
        }
        /**
         * This loads an assembly from the specified filename. The filename allows a local URL (starting with a file:// prefix). If a file prefix is used, the filename is interpreted as a URL, and the filename is URL-decoded.
         * Otherwise the file is treated as a local path.
         * First, an attempt is made to load the assembly from the bundled executable (for those deployments that have been done with the mkbundle tool or for scenarios where the assembly has been registered as an embedded assembly).
         * If this is not the case, then the assembly is loaded from disk using MonoImage.openFull.
         * If the pointed assembly does not live in the Global Assembly Cache, a shadow copy of the assembly is made.
         * @param {string} filename - Opens the assembly pointed out by this name
         * @returns {MonoAssembly}
         */
        static open(filename) {
            const status = Memory.alloc(Process.pointerSize);
            const address = mono_assembly_open(Memory.allocUtf8String(filename), status);
            if (address.isNull()) {
                throw new Error('Failed opening MonoAssembly! Error: ' + MonoImageOpenStatus[status.readInt()]);
            }
            return MonoAssembly.fromAddress(address);
        }
        /**
         * @param {string} filename - Opens the assembly pointed out by this name
         * @param {boolean} refOnly
         * @returns {MonoAssembly}
         */
        static openFull(filename, refOnly) {
            const status = Memory.alloc(Process.pointerSize);
            const address = mono_assembly_open_full(Memory.allocUtf8String(filename), status, refOnly);
            if (address.isNull()) {
                throw new Error('Failed opening MonoAssembly! Error: ' + MonoImageOpenStatus[status.readInt()]);
            }
            return MonoAssembly.fromAddress(address);
        }
        /**
         * Use this method to override the standard assembly lookup system and override any assemblies coming from the GAC. This is the method that supports the MONO_PATH variable.
         * Notice that MONO_PATH and this method are really a very bad idea as it prevents the GAC from working and it prevents the standard resolution mechanisms from working.
         * Nonetheless, for some debugging situations and bootstrapping setups, this is useful to have.
         * @param {string} path - List of paths that contain directories where Mono will look for assemblies
         */
        static setAssembliesPath(path) {
            mono_set_assemblies_path(Memory.allocUtf8String(path));
        }
        /**
         *
         * @param {(assembly: MonoAssembly) => void} callback
         */
        static foreach(callback) {
            mono_assembly_foreach(new NativeCallback((address /*, userData: NativePointer*/) => {
                callback(MonoAssembly.fromAddress(address));
            }, 'void', ['pointer', 'pointer']), NULL);
        }
    }

    class MonoType extends MonoBase {
    }

    class MonoEvent extends MonoBase {
    }

    const mono_field_get_data = createNativeFunction('mono_field_get_data', 'pointer', ['pointer']);
    const mono_field_get_offset = createNativeFunction('mono_field_get_offset', 'uint32', ['pointer']);
    const mono_field_full_name = createNativeFunction('mono_field_full_name', 'pointer', ['pointer']);
    class MonoClassField extends MonoBase {
        /**
         * @returns {string} A pointer to the metadata constant value or to the field data if it has an RVA flag.
         */
        get data() {
            const address = mono_field_get_data(this.$address);
            return address.readUtf8String();
        }
        /**
         * @returns {string} The full name for the field, made up of the namespace, type name and the field name.
         */
        get fullName() {
            const address = mono_field_full_name(this.$address);
            return address.readUtf8String();
        }
        /**
         * @returns {number} The field offset.
         */
        get offset() {
            return mono_field_get_offset(this.$address);
        }
    }

    class MonoVTable extends MonoBase {
    }

    // guint32 mono_class_get_property_token (MonoProperty *prop)
    class MonoProperty extends MonoBase {
    }

    const mono_method_can_access_field = createNativeFunction('mono_method_can_access_field', 'bool', ['pointer', 'pointer']);
    const mono_method_can_access_method = createNativeFunction('mono_method_can_access_method', 'bool', ['pointer', 'pointer']);
    class MonoMethod extends MonoBase {
        /**
         * Used to determine if a method is allowed to access the specified field.
         * @param {MonoClassField} field - The field to access
         * @returns {boolean} TRUE if the given method is allowed to access the field while following the accessibility rules of the CLI.
         */
        canAccessField(field) {
            return mono_method_can_access_field(this.$address, field.$address);
        }
        /**
         * Used to determine if the method is allowed to access the specified called method.
         * @param {MonoMethod} called - The method that we want to probe for accessibility.
         * @returns {boolean} TRUE if the given method is allowed to invoke the called while following the accessibility rules of the CLI.
         */
        canAccessMethod(called) {
            return mono_method_can_access_method(this.$address, called.$address);
        }
    }

    const mono_class_get = createNativeFunction('mono_class_get', 'pointer', ['pointer', 'uint32']);
    const mono_class_get_fields = createNativeFunction('mono_class_get_fields', 'pointer', ['pointer', 'pointer']);
    const mono_class_from_name = createNativeFunction('mono_class_from_name', 'pointer', ['pointer', 'pointer', 'pointer']);
    const mono_class_from_mono_type = createNativeFunction('mono_class_from_mono_type', 'pointer', ['pointer']);
    const mono_class_from_name_case_checked = createNativeFunction('mono_class_from_name_case_checked', 'pointer', ['pointer', 'pointer', 'pointer', 'pointer']);
    const mono_class_from_typeref = createNativeFunction('mono_class_from_typeref', 'pointer', ['pointer', 'uint32']);
    const mono_class_from_typeref_checked = createNativeFunction('mono_class_from_typeref_checked', 'pointer', ['pointer', 'uint32', 'pointer']);
    const mono_class_from_generic_parameter = createNativeFunction('mono_class_from_generic_parameter', 'pointer', ['pointer', 'pointer', 'bool']);
    const mono_class_array_element_size = createNativeFunction('mono_class_array_element_size', 'int32', ['pointer']);
    const mono_class_data_size = createNativeFunction('mono_class_data_size', 'int32', ['pointer']);
    const mono_class_enum_basetype = createNativeFunction('mono_class_enum_basetype', 'pointer', ['pointer']);
    const mono_class_get_byref_type = createNativeFunction('mono_class_get_byref_type', 'pointer', ['pointer']);
    const mono_class_get_element_class = createNativeFunction('mono_class_get_element_class', 'pointer', ['pointer']);
    const mono_class_get_field = createNativeFunction('mono_class_get_field', 'pointer', ['pointer', 'uint32']);
    const mono_class_get_flags = createNativeFunction('mono_class_get_flags', 'int32', ['pointer']);
    const mono_class_get_image = createNativeFunction('mono_class_get_image', 'pointer', ['pointer']);
    const mono_class_get_interfaces = createNativeFunction('mono_class_get_interfaces', 'pointer', ['pointer', 'pointer']);
    const mono_class_get_name = createNativeFunction('mono_class_get_name', 'pointer', ['pointer']);
    const mono_class_get_namespace = createNativeFunction('mono_class_get_namespace', 'pointer', ['pointer']);
    const mono_class_get_nesting_type = createNativeFunction('mono_class_get_nesting_type', 'pointer', ['pointer']);
    const mono_class_get_parent = createNativeFunction('mono_class_get_parent', 'pointer', ['pointer']);
    const mono_class_get_rank = createNativeFunction('mono_class_get_rank', 'int', ['pointer']);
    const mono_class_get_type = createNativeFunction('mono_class_get_type', 'pointer', ['pointer']);
    const mono_class_get_type_token = createNativeFunction('mono_class_get_type_token', 'uint32', ['pointer']);
    const mono_class_implements_interface = createNativeFunction('mono_class_implements_interface', 'bool', ['pointer', 'pointer']);
    const mono_class_init = createNativeFunction('mono_class_init', 'bool', ['pointer']);
    const mono_class_instance_size = createNativeFunction('mono_class_instance_size', 'int32', ['pointer']);
    const mono_class_is_assignable_from = createNativeFunction('mono_class_is_assignable_from', 'bool', ['pointer', 'pointer']);
    const mono_class_is_delegate = createNativeFunction('mono_class_is_delegate', 'bool', ['pointer']);
    const mono_class_is_enum = createNativeFunction('mono_class_is_enum', 'bool', ['pointer']);
    const mono_class_is_subclass_of = createNativeFunction('mono_class_is_subclass_of', 'bool', ['pointer', 'pointer', 'bool']);
    const mono_class_is_valuetype = createNativeFunction('mono_class_is_valuetype', 'bool', ['pointer']);
    const mono_class_min_align = createNativeFunction('mono_class_min_align', 'int32', ['pointer']);
    const mono_class_num_events = createNativeFunction('mono_class_num_events', 'int', ['pointer']);
    const mono_class_num_fields = createNativeFunction('mono_class_num_fields', 'int', ['pointer']);
    const mono_class_num_methods = createNativeFunction('mono_class_num_methods', 'int', ['pointer']);
    const mono_class_num_properties = createNativeFunction('mono_class_num_properties', 'int', ['pointer']);
    const mono_class_value_size = createNativeFunction('mono_class_value_size', 'int32', ['pointer', 'pointer']);
    const mono_class_vtable = createNativeFunction('mono_class_vtable', 'pointer', ['pointer', 'pointer']);
    const mono_class_get_field_from_name = createNativeFunction('mono_class_get_field_from_name', 'pointer', ['pointer', 'pointer']);
    const mono_class_get_methods = createNativeFunction('mono_class_get_methods', 'pointer', ['pointer', 'pointer']);
    const mono_class_get_method_from_name = createNativeFunction('mono_class_get_method_from_name', 'pointer', ['pointer', 'pointer', 'int']);
    const mono_class_get_method_from_name_flags = createNativeFunction('mono_class_get_method_from_name_flags', 'pointer', ['pointer', 'pointer', 'int', 'int']);
    const mono_class_get_nested_types = createNativeFunction('mono_class_get_nested_types', 'pointer', ['pointer', 'pointer']);
    const mono_class_get_properties = createNativeFunction('mono_class_get_properties', 'pointer', ['pointer', 'pointer']);
    const mono_class_get_property_from_name = createNativeFunction('mono_class_get_property_from_name', 'pointer', ['pointer', 'pointer']);
    const mono_class_get_events = createNativeFunction('mono_class_get_events', 'pointer', ['pointer', 'pointer']);
    /**
     * Mono doc: http://docs.go-mono.com/?link=xhtml%3adeploy%2fmono-api-class.html
     */
    class MonoClass extends MonoBase {
        /**
         * @returns {string} The namespace of the class.
         */
        get namespace() {
            return mono_class_get_namespace(this.$address).readUtf8String();
        }
        /**
         * @returns {string} The name of the class.
         */
        get name() {
            return mono_class_get_name(this.$address).readUtf8String();
        }
        /**
         * Use to get the size of a class in bytes.
         * @returns {number} The size of an object instance
         */
        get instanceSize() {
            return mono_class_instance_size(this.$address);
        }
        /**
         * @returns {number} The number of bytes an element of type klass uses when stored into an array.
         */
        get arrayElementSize() {
            return mono_class_array_element_size(this.$address);
        }
        /**
         * @returns {number} The number of bytes an element of type klass uses when stored into an array.
         */
        get dataSize() {
            return mono_class_data_size(this.$address);
        }
        /**
         * Use to get the computed minimum alignment requirements for the specified class.
         * @returns {number} Minimum alignment requirements
         */
        get minAlign() {
            return mono_class_min_align(this.$address);
        }
        /**
         * This works only if klass is non-generic, or a generic type definition.
         * @returns {Array<MonoClass>}
         */
        get nestedTypes() {
            const types = [];
            const iter = Memory.alloc(Process.pointerSize);
            let address;
            while (!(address = mono_class_get_nested_types(this.$address, iter)).isNull()) {
                types.push(MonoClass.fromAddress(address));
            }
            return types;
        }
        /**
         * @returns {number} The number of events in the class.
         */
        get numEvents() {
            return mono_class_num_events(this.$address);
        }
        /**
         * @returns {number} The number of static and instance fields in the class.
         */
        get numFields() {
            return mono_class_num_fields(this.$address);
        }
        /**
         * @returns {number} The number of methods in the class.
         */
        get numMethods() {
            return mono_class_num_methods(this.$address);
        }
        /**
         * @returns {number} The number of properties in the class.
         */
        get numProperties() {
            return mono_class_num_properties(this.$address);
        }
        /**
         * @returns {Array<MonoProperty>} The properties
         */
        get properties() {
            const properties = [];
            const iter = Memory.alloc(Process.pointerSize);
            let address;
            while (!(address = mono_class_get_properties(this.$address, iter)).isNull()) {
                properties.push(MonoProperty.fromAddress(address));
            }
            return properties;
        }
        /**
         * This method returns the internal Type representation for the class.
         * @returns {MonoType} The MonoType from the class.
         */
        get type() {
            const address = mono_class_get_type(this.$address);
            return MonoType.fromAddress(address);
        }
        /**
         * This method returns type token for the class.
         * @returns {number} The type token for the class.
         */
        get typeToken() {
            return mono_class_get_type_token(this.$address);
        }
        /**
         * Use this function to get the underlying type for an enumeration value.
         * @returns {MonoType} The underlying type representation for an enumeration.
         */
        get enumBasetype() {
            const address = mono_class_enum_basetype(this.$address);
            return MonoType.fromAddress(address);
        }
        /**
         * @returns {MonoType}
         */
        get byrefType() {
            const address = mono_class_get_byref_type(this.$address);
            return MonoType.fromAddress(address);
        }
        /**
         * Use this to obtain the class that the provided MonoClass* is nested on.
         * If the return is NULL, this indicates that this class is not nested.
         * @returns {MonoClass} The container type where this type is nested or NULL if this type is not a nested type.
         */
        get nestingType() {
            const address = mono_class_get_nesting_type(this.$address);
            return MonoClass.fromAddress(address);
        }
        /**
         * @returns {MonoClass} The parent class for this class.
         */
        get parent() {
            const address = mono_class_get_parent(this.$address);
            return MonoClass.fromAddress(address);
        }
        /**
         * @returns {number} The rank for the array (the number of dimensions).
         */
        get rank() {
            return mono_class_get_rank(this.$address);
        }
        /**
         * The type flags from the TypeDef table from the metadata. see the TYPE_ATTRIBUTE_* definitions on tabledefs.h for the different values.
         * @returns {number} The flags from the TypeDef table.
         */
        get flags() {
            return mono_class_get_flags(this.$address);
        }
        /**
         * Use this function to get the element class of an array.
         * @returns {MonoClass} - The element class of an array.
         */
        get elementClass() {
            const address = mono_class_get_element_class(this.$address);
            return MonoClass.fromAddress(address);
        }
        /**
         * Returns a list of MonoEvents
         * @returns {Array<MonoEvent>}
         */
        get events() {
            const events = [];
            const iter = Memory.alloc(Process.pointerSize);
            let address;
            while (!(address = mono_class_get_events(this.$address, iter)).isNull()) {
                events.push(MonoEvent.fromAddress(address));
            }
            return events;
        }
        /**
         * Use this method to get the MonoImage* where this class came from.
         * @returns {MonoImage} - The image where this class is defined.
         */
        get image() {
            const address = mono_class_get_image(this.$address);
            return MonoImage.fromAddress(address);
        }
        /**
         * @returns {boolean} TRUE if the MonoClass represents a System.Delegate.
         */
        get isDelegate() {
            // TODO: Check if this really returns bool or something else. In docu they say "mono_bool"
            return mono_class_is_delegate(this.$address);
        }
        /**
         * Use this to determine if the provided MonoClass* represents a value type, or a reference type.
         * @returns {boolean} TRUE if the MonoClass represents a ValueType, FALSE if it represents a reference type.
         */
        get isValuetype() {
            return mono_class_is_valuetype(this.$address);
        }
        /**
         * Use this to determine if the provided MonoClass* represents an enumeration.
         * @returns {boolean} TRUE if the MonoClass represents an enumeration.
         */
        get isEnum() {
            return mono_class_is_enum(this.$address);
        }
        /**
         *  This is for retrieving the interfaces implemented by this class.
         * @returns {Array<MonoClass>} Returns a list of interfaces implemented by this class
         */
        get interfaces() {
            const interfaces = [];
            const iter = Memory.alloc(Process.pointerSize);
            let address;
            while (!(address = mono_class_get_interfaces(this.$address, iter)).isNull()) {
                interfaces.push(MonoClass.fromAddress(address));
            }
            return interfaces;
        }
        /**
         *  This is for retrieving the methods of this class.
         * @returns {Array<MonoMethod>} Returns a list of methods implemented by this class
         */
        get methods() {
            const methods = [];
            const iter = Memory.alloc(Process.pointerSize);
            let address;
            while (!(address = mono_class_get_methods(this.$address, iter)).isNull()) {
                methods.push(MonoMethod.fromAddress(address));
            }
            return methods;
        }
        /**
         * Compute the instance_size, class_size and other infos that cannot be computed at mono_class_get() time. Also compute vtable_size if possible.
         * Returns TRUE on success or FALSE if there was a problem in loading the type (incorrect assemblies, missing assemblies, methods, etc).
         * LOCKING: Acquires the loader lock.
         * @returns {boolean} Returns true on success
         */
        init() {
            return mono_class_init(this.$address);
        }
        /**
         * @param {MonoClass} iface - The interface to check if klass implements.
         * @returns {boolean} TRUE if class implements interface.
         */
        implementsInterface(iface) {
            return mono_class_implements_interface(this.$address, iface.$address);
        }
        /**
         * @param {MonoClass} oClass The other class
         * @returns {boolean} TRUE if an instance of object oClass can be assigned to an instance of object klass
         */
        isAssignableFrom(oClass) {
            return mono_class_is_assignable_from(this.$address, oClass.$address);
        }
        /**
         * This method determines whether klass is a subclass of oClass.
         * If the checkInterfaces flag is set, then if oClass is an interface this method return TRUE if the klass implements the interface or if klass is an interface, if one of its base classes is klass.
         * If check_interfaces is false then, then if klass is not an interface then it returns TRUE if the klass is a subclass of oClass.
         * if klass is an interface and oClass is System.Object, then this function return true.
         * @param {MonoClass} oClass The class we suspect is the base class
         * @param {boolean}   checkInterfaces Whether we should perform interface checks
         * @returns {boolean}
         */
        isSubclassOf(oClass, checkInterfaces) {
            return mono_class_is_subclass_of(this.$address, oClass.$address, checkInterfaces);
        }
        /**
         * This function is used for value types, and return the space and the alignment to store that kind of value object.
         * @param {number} align ?
         * @returns {number} The size of a value of kind klass
         */
        getValueSize( /*align: number*/) {
            // TODO: Take a better look at this function. Im not sure how align should be handled :/
            return mono_class_value_size(this.$address, NULL);
        }
        /**
         * @param {number} fieldToken - The field token
         * @returns {MonoClassField} A MonoClassField representing the type and offset of the field, or a NULL value if the field does not belong to this class.
         */
        getField(fieldToken) {
            const address = mono_class_get_field(this.$address, fieldToken);
            return MonoClassField.fromAddress(address);
        }
        /**
         *  This is for retrieving the fields in a class.
         * @returns {Array<MonoClassField>} The fields as array of MonoClassField
         */
        getFields() {
            const fields = [];
            const iter = Memory.alloc(Process.pointerSize);
            let field;
            while (!(field = mono_class_get_fields(this.$address, iter)).isNull()) {
                fields.push(field);
            }
            return fields;
        }
        /**
         * Search the class and it's parents for a field with the name name.
         * @param {string} name - The field name
         * @returns {MonoClassField} The MonoClassField of the named field or NULL
         */
        getFieldFromName(name) {
            const address = mono_class_get_field_from_name(this.$address, Memory.allocUtf8String(name));
            return MonoClassField.fromAddress(address);
        }
        /**
         * Obtains a MonoMethod with a given name and number of parameters.
         * It only works if there are no multiple signatures for any given method name.
         * @param {string} name - Name of the method
         * @param {number} paramCount - Number of parameters. -1 for any number
         * @returns {MonoMethod}
         */
        getMethodFromName(name, paramCount = -1) {
            const address = mono_class_get_method_from_name(this.$address, Memory.allocUtf8String(name), paramCount);
            return MonoMethod.fromAddress(address);
        }
        /**
         * Obtains a MonoMethod with a given name and number of parameters.
         * It only works if there are no multiple signatures for any given method name.
         * @param {string} name - Name of the method.
         * @param {number} paramCount - Number of parameters. -1 for any number.
         * @param {number} flags - Flags which mus be set in the method.
         * @returns {MonoMethod}
         */
        getMethodFromNameFlags(name, paramCount, flags) {
            const address = mono_class_get_method_from_name_flags(this.$address, Memory.allocUtf8String(name), paramCount, flags);
            return MonoMethod.fromAddress(address);
        }
        /**
         * Use this method to lookup a property in this class
         * @param {string} name - Name of the property to lookup in the class
         * @returns {MonoProperty} The MonoProperty with the given name, or NULL if the property does not exist on the klass.
         */
        getPropertyFromName(name) {
            const address = mono_class_get_property_from_name(this.$address, Memory.allocUtf8String(name));
            return MonoProperty.fromAddress(address);
        }
        /**
         * VTables are domain specific because we create domain specific code, and they contain the domain specific static class data. On failure, NULL is returned, and class->exception_type is set.
         * @param {MonoDomain} domain - The application domain
         * @returns {MonoVTable}
         */
        getVTable(domain) {
            const address = mono_class_vtable(domain.$address, this.$address);
            return MonoVTable.fromAddress(address);
        }
        /**
         * Static methods
         */
        /**
         * Returns the MonoClass with the given typeToken on the image
         * @param {MonoImage} image     - Image where the class token will be looked up
         * @param {number}    typeToken - A type token from the image
         * @returns {MonoClass} The MonoClass with the given typeToken on the image
         */
        static fromTypeToken(image, typeToken) {
            const address = mono_class_get(image.$address, typeToken);
            return MonoClass.fromAddress(address);
        }
        /**
         * Obtains a MonoClass with a given namespace and a given name which is located in the given MonoImage.
         * To reference nested classes, use the "/" character as a separator. For example use "Foo/Bar" to reference the class Bar that is nested inside Foo, like this: "class Foo { class Bar {} }".
         * @param {MonoImage} image     - The MonoImage where the type is looked up in
         * @param {string}    namespace - The type namespace
         * @param {string}    name      - The type short name
         * @param {boolean}   caseSensitive - Whether the namespace/name should be checked for case sensitivity
         * @returns {MonoClass} The MonoClass with the given typeToken on the image
         */
        static fromName(image, namespace, name, caseSensitive = false) {
            let address;
            if (!caseSensitive) {
                address = mono_class_from_name(image.$address, Memory.allocUtf8String(namespace), Memory.allocUtf8String(name));
            }
            else {
                const errPtr = Memory.alloc(Process.pointerSize);
                address = mono_class_from_name_case_checked(image.$address, Memory.allocUtf8String(namespace), Memory.allocUtf8String(name), errPtr);
                if (address.isNull()) {
                    if (!errPtr.isNull())
                        throw new Error('Error handling not implemented!');
                    return null;
                }
            }
            return MonoClass.fromAddress(address);
        }
        /**
         * This returns a MonoClass for the specified MonoType, the value is never NULL.
         * @param {MonoType} monoType     - The MonoImage where the type is looked up in
         * @returns {MonoClass} A MonoClass for the specified MonoType, the value is never NULL.
         */
        static fromMonoType(monoType) {
            const address = mono_class_from_mono_type(monoType.$address);
            return MonoClass.fromAddress(address);
        }
        /**
         * Creates the MonoClass* structure representing the type defined by the typeref token valid inside image.
         * @param {MonoImage} image     - A MonoImage
         * @param {number}    typeToken - A TypeRef token
         * @returns {MonoClass} The MonoClass* representing the typeref token, NULL ifcould not be loaded.
         */
        static fromTyperef(image, typeToken) {
            const address = mono_class_from_typeref(image.$address, typeToken);
            return MonoClass.fromAddress(address);
        }
        /**
         * Creates the MonoClass* structure representing the type defined by the typeref token valid inside image.
         * @param {MonoImage} image     - A MonoImage
         * @param {number}    typeToken - A TypeRef token
         * @returns {MonoClass} The MonoClass* representing the typeref token, NULL ifcould not be loaded.
         */
        static fromTyperefChecked(image, typeToken) {
            const errPtr = Memory.alloc(Process.pointerSize);
            const classAddress = mono_class_from_typeref_checked(image.$address, typeToken, errPtr);
            if (classAddress.isNull()) {
                if (!errPtr.isNull())
                    throw new Error('Error handling not implemented!');
                return null;
            }
            return MonoClass.fromAddress(classAddress);
        }
        /**
         * @param {MonoGenericParam} param - Parameter to find/construct a class for.
         * @returns {MonoClass}
         */
        static fromGenericParameter(param) {
            const address = mono_class_from_generic_parameter(param.$address, NULL, false);
            return MonoClass.fromAddress(address);
        }
    }

    class MonoDomain extends MonoBase {
    }

    class MonoGenericParam extends MonoBase {
    }

    var index$1 = /*#__PURE__*/Object.freeze({
        __proto__: null,
        MonoAssembly: MonoAssembly,
        MonoClass: MonoClass,
        MonoClassField: MonoClassField,
        MonoDomain: MonoDomain,
        MonoEvent: MonoEvent,
        MonoGenericParam: MonoGenericParam,
        MonoImage: MonoImage,
        MonoMethod: MonoMethod,
        MonoType: MonoType,
        MonoVTable: MonoVTable
    });

    /* eslint-disable @typescript-eslint/no-unused-vars */
    MonoAssembly.foreach((assembly) => {
        console.log(assembly.image.fileName);
    });
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

    exports.api = index$1;
    exports.core = index;

    Object.defineProperty(exports, '__esModule', { value: true });

})));
