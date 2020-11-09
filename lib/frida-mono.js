(function (factory) {
    typeof define === 'function' && define.amd ? define(factory) :
    factory();
}((function () { 'use strict';

    /*! *****************************************************************************
    Copyright (c) Microsoft Corporation.

    Permission to use, copy, modify, and/or distribute this software for any
    purpose with or without fee is hereby granted.

    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
    REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
    AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
    INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
    LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
    OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
    PERFORMANCE OF THIS SOFTWARE.
    ***************************************************************************** */
    /* global Reflect, Promise */

    var extendStatics = function(d, b) {
        extendStatics = Object.setPrototypeOf ||
            ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
            function (d, b) { for (var p in b) if (Object.prototype.hasOwnProperty.call(b, p)) d[p] = b[p]; };
        return extendStatics(d, b);
    };

    function __extends(d, b) {
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    }

    var MonoBase = /** @class */ (function () {
        function MonoBase(address) {
            this.$address = NULL;
            this.$address = address;
        }
        MonoBase.fromAddress = function (address) {
            if (address.isNull())
                return null;
            var addressNumber = address.toInt32();
            if (this.cache[addressNumber] === undefined) {
                this.cache[addressNumber] = new this(address);
            }
            return this.cache[addressNumber];
        };
        MonoBase.cache = {};
        return MonoBase;
    }());

    var MonoDomain = /** @class */ (function (_super) {
        __extends(MonoDomain, _super);
        function MonoDomain() {
            return _super !== null && _super.apply(this, arguments) || this;
        }
        return MonoDomain;
    }(MonoBase));

    var KNOWN_RUNTIMES = ['mono.dll', 'libmonosgen-2.0.so'];
    var KNOWN_EXPORTS = ['mono_thread_attach'];
    var KNOWN_STRINGS = ["'%s' in MONO_PATH doesn't exist or has wrong permissions"];
    /**
     * To work with mono we need the mono module thats loaded in the current process.
     * This function tries to find it using 3 methods.
     * - Find by module name
     * - Find by export function names
     * - Find by strings in memory
     */
    function findMonoModule() {
        for (var _i = 0, KNOWN_RUNTIMES_1 = KNOWN_RUNTIMES; _i < KNOWN_RUNTIMES_1.length; _i++) {
            var runtime = KNOWN_RUNTIMES_1[_i];
            var module = Process.findModuleByName(runtime);
            if (module)
                return module;
        }
        for (var _a = 0, KNOWN_EXPORTS_1 = KNOWN_EXPORTS; _a < KNOWN_EXPORTS_1.length; _a++) {
            var exportName = KNOWN_EXPORTS_1[_a];
            var exportFunction = Module.findExportByName(null, exportName);
            if (exportFunction)
                return Process.findModuleByAddress(exportFunction);
        }
        var allModules = Process.enumerateModules();
        for (var _b = 0, allModules_1 = allModules; _b < allModules_1.length; _b++) {
            var module = allModules_1[_b];
            for (var _c = 0, KNOWN_STRINGS_1 = KNOWN_STRINGS; _c < KNOWN_STRINGS_1.length; _c++) {
                var string = KNOWN_STRINGS_1[_c];
                var pattern = string
                    .split('')
                    .map(function (e) { return ('0' + e.charCodeAt(0).toString(16)).slice(-2); })
                    .join(' ');
                var matches = Memory.scanSync(module.base, module.size, pattern);
                if (matches.length > 0) {
                    return Process.findModuleByAddress(matches[0].address);
                }
            }
        }
        throw new Error('Failed finding the mono module!');
    }
    var module = findMonoModule();

    /**
     * This is just to make it convinient to use NativeFunctions.
     * Otherwise we would have to store the informations somewhere else.
     * This way its attached to the NativeFunction. Awesome!
     */
    var ExNativeFunction = /** @class */ (function (_super) {
        __extends(ExNativeFunction, _super);
        function ExNativeFunction(address, retType, argTypes, abiOrOptions) {
            if (retType === void 0) { retType = 'void'; }
            if (argTypes === void 0) { argTypes = []; }
            if (abiOrOptions === void 0) { abiOrOptions = 'default'; }
            var _this = _super.call(this) || this;
            _this.abi = 'default';
            var native = new NativeFunction(address, retType, argTypes, abiOrOptions);
            _this.address = address;
            _this.retType = retType;
            _this.argTypes = argTypes;
            if (typeof abiOrOptions === 'string') {
                _this.abi = abiOrOptions;
            }
            else if (typeof abiOrOptions === 'object') {
                _this.abi = abiOrOptions.abi || 'default';
                _this.options = abiOrOptions;
            }
            Object.assign(native, _this);
            return native;
        }
        ExNativeFunction.prototype.nativeCallback = function (callback) {
            return new NativeCallback(callback, this.retType, this.argTypes, this.abi);
        };
        ExNativeFunction.prototype.intercept = function (callbacksOrProbe, data) {
            return Interceptor.attach(this.address, callbacksOrProbe, data);
        };
        ExNativeFunction.prototype.replace = function (replacement, data) {
            return Interceptor.replace(this.address, replacement, data);
        };
        return ExNativeFunction;
    }(Function));

    function createNativeFunction(name, retType, argTypes, abiOrOptions) {
        if (abiOrOptions === void 0) { abiOrOptions = 'default'; }
        var address = Module.findExportByName(module.name, name);
        if (!address) {
            console.warn('Warning! Native mono export not found! Expected export: ' + name);
            return null;
        }
        return new ExNativeFunction(address, retType, argTypes, abiOrOptions);
    }

    var mono_table_info_get_rows = createNativeFunction('mono_table_info_get_rows', 'int', ['pointer']);
    var MonoTableInfo = /** @class */ (function (_super) {
        __extends(MonoTableInfo, _super);
        function MonoTableInfo() {
            return _super !== null && _super.apply(this, arguments) || this;
        }
        Object.defineProperty(MonoTableInfo.prototype, "rowSize", {
            get: function () {
                return mono_table_info_get_rows(this.$address);
            },
            enumerable: false,
            configurable: true
        });
        return MonoTableInfo;
    }(MonoBase));

    var mono_image_loaded = createNativeFunction('mono_image_loaded', 'pointer', ['pointer']);
    var mono_image_get_filename = createNativeFunction('mono_image_get_filename', 'pointer', ['pointer']);
    var mono_image_get_name = createNativeFunction('mono_image_get_name', 'pointer', ['pointer']);
    var mono_image_get_table_info = createNativeFunction('mono_image_get_table_info', 'pointer', ['pointer', 'int']);
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
    var MonoImage = /** @class */ (function (_super) {
        __extends(MonoImage, _super);
        function MonoImage() {
            return _super !== null && _super.apply(this, arguments) || this;
        }
        Object.defineProperty(MonoImage.prototype, "fileName", {
            get: function () {
                return mono_image_get_filename(this.$address).readUtf8String();
            },
            enumerable: false,
            configurable: true
        });
        Object.defineProperty(MonoImage.prototype, "name", {
            get: function () {
                return mono_image_get_name(this.$address).readUtf8String();
            },
            enumerable: false,
            configurable: true
        });
        MonoImage.prototype.getTableInfo = function (tableId) {
            var address = mono_image_get_table_info(this.$address, tableId);
            return MonoTableInfo.fromAddress(address);
        };
        /**
         * Static methods
         */
        MonoImage.loaded = function (assemblyName) {
            var address = mono_image_loaded(Memory.allocUtf8String(assemblyName));
            return MonoImage.fromAddress(address);
        };
        return MonoImage;
    }(MonoBase));

    var MonoType = /** @class */ (function (_super) {
        __extends(MonoType, _super);
        function MonoType() {
            return _super !== null && _super.apply(this, arguments) || this;
        }
        return MonoType;
    }(MonoBase));

    // guint32 mono_class_get_field_token (MonoClassField *field)
    var MonoClassField = /** @class */ (function (_super) {
        __extends(MonoClassField, _super);
        function MonoClassField() {
            return _super !== null && _super.apply(this, arguments) || this;
        }
        return MonoClassField;
    }(MonoBase));

    var MonoVTable = /** @class */ (function (_super) {
        __extends(MonoVTable, _super);
        function MonoVTable() {
            return _super !== null && _super.apply(this, arguments) || this;
        }
        return MonoVTable;
    }(MonoBase));

    var MonoMethod = /** @class */ (function (_super) {
        __extends(MonoMethod, _super);
        function MonoMethod() {
            return _super !== null && _super.apply(this, arguments) || this;
        }
        return MonoMethod;
    }(MonoBase));

    var mono_class_get = createNativeFunction('mono_class_get', 'pointer', ['pointer', 'uint32']);
    var mono_class_get_fields = createNativeFunction('mono_class_get_fields', 'pointer', ['pointer', 'pointer']);
    var mono_class_from_name = createNativeFunction('mono_class_from_name', 'pointer', ['pointer', 'pointer', 'pointer']);
    var mono_class_from_mono_type = createNativeFunction('mono_class_from_mono_type', 'pointer', ['pointer']);
    var mono_class_from_name_case_checked = createNativeFunction('mono_class_from_name_case_checked', 'pointer', ['pointer', 'pointer', 'pointer', 'pointer']);
    var mono_class_from_typeref = createNativeFunction('mono_class_from_typeref', 'pointer', ['pointer', 'uint32']);
    var mono_class_from_typeref_checked = createNativeFunction('mono_class_from_typeref_checked', 'pointer', ['pointer', 'uint32', 'pointer']);
    var mono_class_from_generic_parameter = createNativeFunction('mono_class_from_generic_parameter', 'pointer', ['pointer', 'pointer', 'bool']);
    var mono_class_array_element_size = createNativeFunction('mono_class_array_element_size', 'int32', ['pointer']);
    var mono_class_data_size = createNativeFunction('mono_class_data_size', 'int32', ['pointer']);
    var mono_class_enum_basetype = createNativeFunction('mono_class_enum_basetype', 'pointer', ['pointer']);
    var mono_class_get_byref_type = createNativeFunction('mono_class_get_byref_type', 'pointer', ['pointer']);
    var mono_class_get_element_class = createNativeFunction('mono_class_get_element_class', 'pointer', ['pointer']);
    var mono_class_get_field = createNativeFunction('mono_class_get_field', 'pointer', ['pointer', 'uint32']);
    var mono_class_get_flags = createNativeFunction('mono_class_get_flags', 'int32', ['pointer']);
    var mono_class_get_image = createNativeFunction('mono_class_get_image', 'pointer', ['pointer']);
    var mono_class_get_interfaces = createNativeFunction('mono_class_get_interfaces', 'pointer', ['pointer', 'pointer']);
    var mono_class_get_name = createNativeFunction('mono_class_get_name', 'pointer', ['pointer']);
    var mono_class_get_namespace = createNativeFunction('mono_class_get_namespace', 'pointer', ['pointer']);
    var mono_class_get_nesting_type = createNativeFunction('mono_class_get_nesting_type', 'pointer', ['pointer']);
    var mono_class_get_parent = createNativeFunction('mono_class_get_parent', 'pointer', ['pointer']);
    var mono_class_get_rank = createNativeFunction('mono_class_get_rank', 'int', ['pointer']);
    var mono_class_get_type = createNativeFunction('mono_class_get_type', 'pointer', ['pointer']);
    var mono_class_get_type_token = createNativeFunction('mono_class_get_type_token', 'uint32', ['pointer']);
    var mono_class_implements_interface = createNativeFunction('mono_class_implements_interface', 'bool', ['pointer', 'pointer']);
    var mono_class_init = createNativeFunction('mono_class_init', 'bool', ['pointer']);
    var mono_class_instance_size = createNativeFunction('mono_class_instance_size', 'int32', ['pointer']);
    var mono_class_is_assignable_from = createNativeFunction('mono_class_is_assignable_from', 'bool', ['pointer', 'pointer']);
    var mono_class_is_delegate = createNativeFunction('mono_class_is_delegate', 'bool', ['pointer']);
    var mono_class_is_enum = createNativeFunction('mono_class_is_enum', 'bool', ['pointer']);
    var mono_class_is_subclass_of = createNativeFunction('mono_class_is_subclass_of', 'bool', ['pointer', 'pointer', 'bool']);
    var mono_class_is_valuetype = createNativeFunction('mono_class_is_valuetype', 'bool', ['pointer']);
    var mono_class_min_align = createNativeFunction('mono_class_min_align', 'int32', ['pointer']);
    var mono_class_num_events = createNativeFunction('mono_class_num_events', 'int', ['pointer']);
    var mono_class_num_fields = createNativeFunction('mono_class_num_fields', 'int', ['pointer']);
    var mono_class_num_methods = createNativeFunction('mono_class_num_methods', 'int', ['pointer']);
    var mono_class_num_properties = createNativeFunction('mono_class_num_properties', 'int', ['pointer']);
    var mono_class_value_size = createNativeFunction('mono_class_value_size', 'int32', ['pointer', 'pointer']);
    var mono_class_vtable = createNativeFunction('mono_class_vtable', 'pointer', ['pointer', 'pointer']);
    var mono_class_get_field_from_name = createNativeFunction('mono_class_get_field_from_name', 'pointer', ['pointer', 'pointer']);
    var mono_class_get_methods = createNativeFunction('mono_class_get_methods', 'pointer', ['pointer', 'pointer']);
    /**
     * Mono doc: http://docs.go-mono.com/?link=xhtml%3adeploy%2fmono-api-class.html
     */
    var MonoClass = /** @class */ (function (_super) {
        __extends(MonoClass, _super);
        function MonoClass() {
            return _super !== null && _super.apply(this, arguments) || this;
        }
        Object.defineProperty(MonoClass.prototype, "namespace", {
            /**
             * @returns {string} The namespace of the class.
             */
            get: function () {
                return mono_class_get_namespace(this.$address).readUtf8String();
            },
            enumerable: false,
            configurable: true
        });
        Object.defineProperty(MonoClass.prototype, "name", {
            /**
             * @returns {string} The name of the class.
             */
            get: function () {
                return mono_class_get_name(this.$address).readUtf8String();
            },
            enumerable: false,
            configurable: true
        });
        Object.defineProperty(MonoClass.prototype, "instanceSize", {
            /**
             * Use to get the size of a class in bytes.
             * @returns {number} The size of an object instance
             */
            get: function () {
                return mono_class_instance_size(this.$address);
            },
            enumerable: false,
            configurable: true
        });
        Object.defineProperty(MonoClass.prototype, "arrayElementSize", {
            /**
             * @returns {number} The number of bytes an element of type klass uses when stored into an array.
             */
            get: function () {
                return mono_class_array_element_size(this.$address);
            },
            enumerable: false,
            configurable: true
        });
        Object.defineProperty(MonoClass.prototype, "dataSize", {
            /**
             * @returns {number} The number of bytes an element of type klass uses when stored into an array.
             */
            get: function () {
                return mono_class_data_size(this.$address);
            },
            enumerable: false,
            configurable: true
        });
        Object.defineProperty(MonoClass.prototype, "minAlign", {
            /**
             * Use to get the computed minimum alignment requirements for the specified class.
             * @returns {number} Minimum alignment requirements
             */
            get: function () {
                return mono_class_min_align(this.$address);
            },
            enumerable: false,
            configurable: true
        });
        Object.defineProperty(MonoClass.prototype, "numEvents", {
            /**
             * @returns {number} The number of events in the class.
             */
            get: function () {
                return mono_class_num_events(this.$address);
            },
            enumerable: false,
            configurable: true
        });
        Object.defineProperty(MonoClass.prototype, "numFields", {
            /**
             * @returns {number} The number of static and instance fields in the class.
             */
            get: function () {
                return mono_class_num_fields(this.$address);
            },
            enumerable: false,
            configurable: true
        });
        Object.defineProperty(MonoClass.prototype, "numMethods", {
            /**
             * @returns {number} The number of methods in the class.
             */
            get: function () {
                return mono_class_num_methods(this.$address);
            },
            enumerable: false,
            configurable: true
        });
        Object.defineProperty(MonoClass.prototype, "numProperties", {
            /**
             * @returns {number} The number of properties in the class.
             */
            get: function () {
                return mono_class_num_properties(this.$address);
            },
            enumerable: false,
            configurable: true
        });
        Object.defineProperty(MonoClass.prototype, "type", {
            /**
             * This method returns the internal Type representation for the class.
             * @returns {MonoType} The MonoType from the class.
             */
            get: function () {
                var address = mono_class_get_type(this.$address);
                return MonoType.fromAddress(address);
            },
            enumerable: false,
            configurable: true
        });
        Object.defineProperty(MonoClass.prototype, "typeToken", {
            /**
             * This method returns type token for the class.
             * @returns {number} The type token for the class.
             */
            get: function () {
                return mono_class_get_type_token(this.$address);
            },
            enumerable: false,
            configurable: true
        });
        Object.defineProperty(MonoClass.prototype, "enumBasetype", {
            /**
             * Use this function to get the underlying type for an enumeration value.
             * @returns {MonoType} The underlying type representation for an enumeration.
             */
            get: function () {
                var address = mono_class_enum_basetype(this.$address);
                return MonoType.fromAddress(address);
            },
            enumerable: false,
            configurable: true
        });
        Object.defineProperty(MonoClass.prototype, "byrefType", {
            /**
             * @returns {MonoType}
             */
            get: function () {
                var address = mono_class_get_byref_type(this.$address);
                return MonoType.fromAddress(address);
            },
            enumerable: false,
            configurable: true
        });
        Object.defineProperty(MonoClass.prototype, "nestingType", {
            /**
             * Use this to obtain the class that the provided MonoClass* is nested on.
             * If the return is NULL, this indicates that this class is not nested.
             * @returns {MonoClass} The container type where this type is nested or NULL if this type is not a nested type.
             */
            get: function () {
                var address = mono_class_get_nesting_type(this.$address);
                return MonoClass.fromAddress(address);
            },
            enumerable: false,
            configurable: true
        });
        Object.defineProperty(MonoClass.prototype, "parent", {
            /**
             * @returns {MonoClass} The parent class for this class.
             */
            get: function () {
                var address = mono_class_get_parent(this.$address);
                return MonoClass.fromAddress(address);
            },
            enumerable: false,
            configurable: true
        });
        Object.defineProperty(MonoClass.prototype, "rank", {
            /**
             * @returns {number} The rank for the array (the number of dimensions).
             */
            get: function () {
                return mono_class_get_rank(this.$address);
            },
            enumerable: false,
            configurable: true
        });
        Object.defineProperty(MonoClass.prototype, "flags", {
            /**
             * The type flags from the TypeDef table from the metadata. see the TYPE_ATTRIBUTE_* definitions on tabledefs.h for the different values.
             * @returns {number} The flags from the TypeDef table.
             */
            get: function () {
                return mono_class_get_flags(this.$address);
            },
            enumerable: false,
            configurable: true
        });
        Object.defineProperty(MonoClass.prototype, "elementClass", {
            /**
             * Use this function to get the element class of an array.
             * @returns {MonoClass} - The element class of an array.
             */
            get: function () {
                var address = mono_class_get_element_class(this.$address);
                return MonoClass.fromAddress(address);
            },
            enumerable: false,
            configurable: true
        });
        Object.defineProperty(MonoClass.prototype, "image", {
            /**
             * Use this method to get the MonoImage* where this class came from.
             * @returns {MonoImage} - The image where this class is defined.
             */
            get: function () {
                var address = mono_class_get_image(this.$address);
                return MonoImage.fromAddress(address);
            },
            enumerable: false,
            configurable: true
        });
        Object.defineProperty(MonoClass.prototype, "isDelegate", {
            /**
             * @returns {boolean} TRUE if the MonoClass represents a System.Delegate.
             */
            get: function () {
                // TODO: Check if this really returns bool or something else. In docu they say "mono_bool"
                return mono_class_is_delegate(this.$address);
            },
            enumerable: false,
            configurable: true
        });
        Object.defineProperty(MonoClass.prototype, "isValuetype", {
            /**
             * Use this to determine if the provided MonoClass* represents a value type, or a reference type.
             * @returns {boolean} TRUE if the MonoClass represents a ValueType, FALSE if it represents a reference type.
             */
            get: function () {
                return mono_class_is_valuetype(this.$address);
            },
            enumerable: false,
            configurable: true
        });
        Object.defineProperty(MonoClass.prototype, "isEnum", {
            /**
             * Use this to determine if the provided MonoClass* represents an enumeration.
             * @returns {boolean} TRUE if the MonoClass represents an enumeration.
             */
            get: function () {
                return mono_class_is_enum(this.$address);
            },
            enumerable: false,
            configurable: true
        });
        Object.defineProperty(MonoClass.prototype, "interfaces", {
            /**
             *  This is for retrieving the interfaces implemented by this class.
             * @returns {Array<MonoClass>} Returns a list of interfaces implemented by this class
             */
            get: function () {
                var interfaces = [];
                var iter = Memory.alloc(Process.pointerSize);
                var address;
                while (!(address = mono_class_get_interfaces(this.$address, iter)).isNull()) {
                    interfaces.push(MonoClass.fromAddress(address));
                }
                return interfaces;
            },
            enumerable: false,
            configurable: true
        });
        Object.defineProperty(MonoClass.prototype, "methods", {
            /**
             *  This is for retrieving the methods of this class.
             * @returns {Array<MonoMethod>} Returns a list of methods implemented by this class
             */
            get: function () {
                var methods = [];
                var iter = Memory.alloc(Process.pointerSize);
                var address;
                while (!(address = mono_class_get_methods(this.$address, iter)).isNull()) {
                    methods.push(MonoMethod.fromAddress(address));
                }
                return methods;
            },
            enumerable: false,
            configurable: true
        });
        /**
         * Compute the instance_size, class_size and other infos that cannot be computed at mono_class_get() time. Also compute vtable_size if possible.
         * Returns TRUE on success or FALSE if there was a problem in loading the type (incorrect assemblies, missing assemblies, methods, etc).
         * LOCKING: Acquires the loader lock.
         * @returns {boolean} Returns true on success
         */
        MonoClass.prototype.init = function () {
            return mono_class_init(this.$address);
        };
        /**
         * @param {MonoClass} iface - The interface to check if klass implements.
         * @returns {boolean} TRUE if class implements interface.
         */
        MonoClass.prototype.implementsInterface = function (iface) {
            return mono_class_implements_interface(this.$address, iface.$address);
        };
        /**
         * @param {MonoClass} oClass The other class
         * @returns {boolean} TRUE if an instance of object oClass can be assigned to an instance of object klass
         */
        MonoClass.prototype.isAssignableFrom = function (oClass) {
            return mono_class_is_assignable_from(this.$address, oClass.$address);
        };
        /**
         * This method determines whether klass is a subclass of oClass.
         * If the checkInterfaces flag is set, then if oClass is an interface this method return TRUE if the klass implements the interface or if klass is an interface, if one of its base classes is klass.
         * If check_interfaces is false then, then if klass is not an interface then it returns TRUE if the klass is a subclass of oClass.
         * if klass is an interface and oClass is System.Object, then this function return true.
         * @param {MonoClass} oClass The class we suspect is the base class
         * @param {boolean}   checkInterfaces Whether we should perform interface checks
         */
        MonoClass.prototype.isSubclassOf = function (oClass, checkInterfaces) {
            return mono_class_is_subclass_of(this.$address, oClass.$address, checkInterfaces);
        };
        /**
         * This function is used for value types, and return the space and the alignment to store that kind of value object.
         * @param {number} align ?
         * @returns {number} The size of a value of kind klass
         */
        MonoClass.prototype.getValueSize = function ( /*align: number*/) {
            // TODO: Take a better look at this function. Im not sure how align should be handled :/
            return mono_class_value_size(this.$address, NULL);
        };
        /**
         * @param {number} fieldToken - The field token
         * @returns {MonoClassField} A MonoClassField representing the type and offset of the field, or a NULL value if the field does not belong to this class.
         */
        MonoClass.prototype.getField = function (fieldToken) {
            var address = mono_class_get_field(this.$address, fieldToken);
            return MonoClassField.fromAddress(address);
        };
        /**
         *  This is for retrieving the fields in a class.
         * @returns {Array<MonoClassField>} The fields as array of MonoClassField
         */
        MonoClass.prototype.getFields = function () {
            var fields = [];
            var iter = Memory.alloc(Process.pointerSize);
            var field;
            while (!(field = mono_class_get_fields(this.$address, iter)).isNull()) {
                fields.push(field);
            }
            return fields;
        };
        /**
         * Search the class and it's parents for a field with the name name.
         * @param {string} name - The field name
         * @returns {MonoClassField} The MonoClassField of the named field or NULL
         */
        MonoClass.prototype.getFieldFromName = function (name) {
            var address = mono_class_get_field_from_name(this.$address, Memory.allocUtf8String(name));
            return MonoClassField.fromAddress(address);
        };
        /**
         * VTables are domain specific because we create domain specific code, and they contain the domain specific static class data. On failure, NULL is returned, and class->exception_type is set.
         * @param {MonoDomain} domain - The application domain
         * @returns {MonoVTable}
         */
        MonoClass.prototype.getVTable = function (domain) {
            var address = mono_class_vtable(domain.$address, this.$address);
            return MonoVTable.fromAddress(address);
        };
        /**
         * Static methods
         */
        /**
         * Returns the MonoClass with the given typeToken on the image
         * @param {MonoImage} image     - Image where the class token will be looked up
         * @param {number}    typeToken - A type token from the image
         * @returns {MonoClass} The MonoClass with the given typeToken on the image
         */
        MonoClass.fromTypeToken = function (image, typeToken) {
            var address = mono_class_get(image.$address, typeToken);
            return MonoClass.fromAddress(address);
        };
        /**
         * Obtains a MonoClass with a given namespace and a given name which is located in the given MonoImage.
         * To reference nested classes, use the "/" character as a separator. For example use "Foo/Bar" to reference the class Bar that is nested inside Foo, like this: "class Foo { class Bar {} }".
         * @param {MonoImage} image     - The MonoImage where the type is looked up in
         * @param {string}    namespace - The type namespace
         * @param {string}    name      - The type short name
         * @param {boolean}   caseSensitive - Whether the namespace/name should be checked for case sensitivity
         * @returns {MonoClass} The MonoClass with the given typeToken on the image
         */
        MonoClass.fromName = function (image, namespace, name, caseSensitive) {
            if (caseSensitive === void 0) { caseSensitive = false; }
            var address;
            if (!caseSensitive) {
                address = mono_class_from_name(image.$address, Memory.allocUtf8String(namespace), Memory.allocUtf8String(name));
            }
            else {
                var errPtr = Memory.alloc(Process.pointerSize);
                address = mono_class_from_name_case_checked(image.$address, Memory.allocUtf8String(namespace), Memory.allocUtf8String(name), errPtr);
                if (address.isNull()) {
                    if (!errPtr.isNull())
                        throw new Error('Error handling not implemented!');
                    return null;
                }
            }
            return MonoClass.fromAddress(address);
        };
        /**
         * This returns a MonoClass for the specified MonoType, the value is never NULL.
         * @param {MonoType} monoType     - The MonoImage where the type is looked up in
         * @returns {MonoClass} A MonoClass for the specified MonoType, the value is never NULL.
         */
        MonoClass.fromMonoType = function (monoType) {
            var address = mono_class_from_mono_type(monoType.$address);
            return MonoClass.fromAddress(address);
        };
        /**
         * Creates the MonoClass* structure representing the type defined by the typeref token valid inside image.
         * @param {MonoImage} image     - A MonoImage
         * @param {number}    typeToken - A TypeRef token
         * @returns {MonoClass} The MonoClass* representing the typeref token, NULL ifcould not be loaded.
         */
        MonoClass.fromTyperef = function (image, typeToken) {
            var address = mono_class_from_typeref(image.$address, typeToken);
            return MonoClass.fromAddress(address);
        };
        /**
         * Creates the MonoClass* structure representing the type defined by the typeref token valid inside image.
         * @param {MonoImage} image     - A MonoImage
         * @param {number}    typeToken - A TypeRef token
         * @returns {MonoClass} The MonoClass* representing the typeref token, NULL ifcould not be loaded.
         */
        MonoClass.fromTyperefChecked = function (image, typeToken) {
            var errPtr = Memory.alloc(Process.pointerSize);
            var classAddress = mono_class_from_typeref_checked(image.$address, typeToken, errPtr);
            if (classAddress.isNull()) {
                if (!errPtr.isNull())
                    throw new Error('Error handling not implemented!');
                return null;
            }
            return MonoClass.fromAddress(classAddress);
        };
        /**
         * @param {MonoGenericParam} param - Parameter to find/construct a class for.
         * @returns {MonoClass}
         */
        MonoClass.fromGenericParameter = function (param) {
            var address = mono_class_from_generic_parameter(param.$address, NULL, false);
            return MonoClass.fromAddress(address);
        };
        return MonoClass;
    }(MonoBase));

    var MonoGenericParam = /** @class */ (function (_super) {
        __extends(MonoGenericParam, _super);
        function MonoGenericParam() {
            return _super !== null && _super.apply(this, arguments) || this;
        }
        return MonoGenericParam;
    }(MonoBase));

    var assemblyCSharp = MonoImage.loaded('Assembly-CSharp');
    var UserMessageManager = MonoClass.fromName(assemblyCSharp, '', 'UserMessageManager');
    console.log(UserMessageManager.arrayElementSize);
    /*const tableInfo = assemblyCSharp.getTableInfo(MonoMetaTableEnum.MONO_TABLE_TYPEDEF)
    console.log(tableInfo.rows)*/
    /*
    const UserMessageManager = MonoClass.fromName(assemblyCSharp, '', 'UserMessageManager')
    console.log(UserMessageManager)
    */

})));
