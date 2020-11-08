(function (factory) {
    typeof define === 'function' && define.amd ? define(factory) :
    factory();
}((function () { 'use strict';

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
            var error_1 = 'Native mono export not found! Expected export: ' + name;
            console.warn(error_1);
            return (function () {
                throw new Error(error_1);
            });
        }
        return new ExNativeFunction(address, retType, argTypes, abiOrOptions);
    }

    var mono_image_loaded = createNativeFunction('mono_image_loaded', 'pointer', ['pointer']);
    var mono_image_get_filename = createNativeFunction('mono_image_get_filename', 'pointer', ['pointer']);
    var mono_image_get_name = createNativeFunction('mono_image_get_name', 'pointer', ['pointer']);
    var cache = {};
    var MonoImage = /** @class */ (function () {
        function MonoImage(options) {
            if (options === void 0) { options = {}; }
            if (options.address) {
                this.$address = options.address;
            }
            else {
                throw new Error('Construction logic not implemented yet. (MonoImage)');
            }
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
        /**
         * Static methods
         */
        MonoImage.loaded = function (assemblyName) {
            var address = mono_image_loaded(Memory.allocUtf8String(assemblyName));
            return MonoImage.fromAddress(address);
        };
        MonoImage.fromAddress = function (address) {
            if (address.isNull())
                return null;
            var addressNumber = address.toInt32();
            if (cache[addressNumber] === undefined) {
                cache[addressNumber] = new MonoImage({ address: address });
            }
            return cache[addressNumber];
        };
        return MonoImage;
    }());

    var cache$1 = {};
    var MonoType = /** @class */ (function () {
        function MonoType(options) {
            if (options === void 0) { options = {}; }
            if (options.address) {
                this.$address = options.address;
            }
            else {
                throw new Error('Construction logic not implemented yet. (MonoType)');
            }
        }
        MonoType.fromAddress = function (address) {
            if (address.isNull())
                return null;
            var addressNumber = address.toInt32();
            if (cache$1[addressNumber] === undefined) {
                cache$1[addressNumber] = new MonoType({ address: address });
            }
            return cache$1[addressNumber];
        };
        return MonoType;
    }());

    // guint32 mono_class_get_field_token (MonoClassField *field)
    var cache$2 = {};
    var MonoClassField = /** @class */ (function () {
        function MonoClassField(options) {
            if (options === void 0) { options = {}; }
            if (options.address) {
                this.$address = options.address;
            }
            else {
                throw new Error('Construction logic not implemented yet. (MonoClassField)');
            }
        }
        MonoClassField.fromAddress = function (address) {
            if (address.isNull())
                return null;
            var addressNumber = address.toInt32();
            if (cache$2[addressNumber] === undefined) {
                cache$2[addressNumber] = new MonoClassField({ address: address });
            }
            return cache$2[addressNumber];
        };
        return MonoClassField;
    }());

    var mono_class_get = createNativeFunction('mono_class_get', 'pointer', ['pointer', 'uint32']);
    var mono_class_get_fields = createNativeFunction('mono_class_get_fields', 'pointer', ['pointer', 'pointer']);
    var mono_class_from_name = createNativeFunction('mono_class_from_name', 'pointer', [
        'pointer',
        'pointer',
        'pointer'
    ]);
    var mono_class_from_mono_type = createNativeFunction('mono_class_from_mono_type', 'pointer', ['pointer']);
    var mono_class_from_name_case_checked = createNativeFunction('mono_class_from_name_case_checked', 'pointer', [
        'pointer',
        'pointer',
        'pointer',
        'pointer'
    ]);
    var mono_class_from_typeref = createNativeFunction('mono_class_from_typeref', 'pointer', ['pointer', 'uint32']);
    var mono_class_from_typeref_checked = createNativeFunction('mono_class_from_typeref_checked', 'pointer', [
        'pointer',
        'uint32',
        'pointer'
    ]);
    var mono_class_array_element_size = createNativeFunction('mono_class_array_element_size', 'int32', ['pointer']);
    var mono_class_data_size = createNativeFunction('mono_class_data_size', 'int32', ['pointer']);
    var mono_class_enum_basetype = createNativeFunction('mono_class_enum_basetype', 'pointer', ['pointer']);
    var mono_class_get_byref_type = createNativeFunction('mono_class_get_byref_type', 'pointer', ['pointer']);
    var mono_class_get_element_class = createNativeFunction('mono_class_get_element_class', 'pointer', ['pointer']);
    var mono_class_get_field = createNativeFunction('mono_class_get_field', 'pointer', ['pointer', 'uint32']);
    var mono_class_get_flags = createNativeFunction('mono_class_get_flags', 'int32', ['pointer']);
    var mono_class_get_image = createNativeFunction('mono_class_get_image', 'pointer', ['pointer']);
    var mono_class_get_interfaces = createNativeFunction('mono_class_get_interfaces', 'pointer', [
        'pointer',
        'pointer'
    ]);
    var mono_class_get_name = createNativeFunction('mono_class_get_name', 'pointer', ['pointer']);
    var mono_class_get_namespace = createNativeFunction('mono_class_get_namespace', 'pointer', ['pointer']);
    var mono_class_get_nesting_type = createNativeFunction('mono_class_get_nesting_type', 'pointer', ['pointer']);
    var mono_class_get_parent = createNativeFunction('mono_class_get_parent', 'pointer', ['pointer']);
    var mono_class_get_rank = createNativeFunction('mono_class_get_rank', 'int', ['pointer']);
    var mono_class_get_type = createNativeFunction('mono_class_get_type', 'pointer', ['pointer']);
    var mono_class_get_type_token = createNativeFunction('mono_class_get_type_token', 'uint32', ['pointer']);
    var mono_class_implements_interface = createNativeFunction('mono_class_implements_interface', 'bool', [
        'pointer',
        'pointer'
    ]);
    var mono_class_init = createNativeFunction('mono_class_init', 'bool', ['pointer']);
    var mono_class_instance_size = createNativeFunction('mono_class_instance_size', 'int32', ['pointer']);
    var cache$3 = {};
    var MonoClass = /** @class */ (function () {
        function MonoClass(options) {
            if (options === void 0) { options = {}; }
            if (options.address) {
                this.$address = options.address;
            }
            else {
                throw new Error('Construction logic not implemented yet. (MonoClass)');
            }
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
         * @param {number} fieldToken - The field token
         * @returns {MonoClassField} A MonoClassField representing the type and offset of the field, or a NULL value if the field does not belong to this class.
         */
        MonoClass.prototype.getField = function (fieldToken) {
            var address = mono_class_get_field(this.$address, fieldToken);
            return MonoClassField.fromAddress(address);
        };
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
         * Static methods
         */
        /**
         * Returns the MonoClass with the given typeToken on the image
         * @param {MonoImage} image     - Image where the class token will be looked up
         * @param {number}    typeToken - A type token from the image
         * @returns {MonoClass} The MonoClass with the given typeToken on the image
         */
        MonoClass.get = function (image, typeToken) {
            var address = mono_class_get(image.$address, typeToken);
            return MonoClass.fromAddress(address);
        };
        /**
         * Obtains a MonoClass with a given namespace and a given name which is located in the given MonoImage.
         * To reference nested classes, use the "/" character as a separator. For example use "Foo/Bar" to reference the class Bar that is nested inside Foo, like this: "class Foo { class Bar {} }".
         * @param {MonoImage} image     - The MonoImage where the type is looked up in
         * @param {string}    namespace - The type namespace
         * @param {string}    name      - The type short name
         * @returns {MonoClass} The MonoClass with the given typeToken on the image
         */
        MonoClass.fromName = function (image, namespace, name) {
            var address = mono_class_from_name(image.$address, Memory.allocUtf8String(namespace), Memory.allocUtf8String(name));
            return MonoClass.fromAddress(address);
        };
        /**
         * Obtains a MonoClass with a given namespace and a given name which is located in the given MonoImage. The namespace and name lookups are case insensitive.
         * @param {MonoImage} image     - The MonoImage where the type is looked up in
         * @param {string}    namespace - The type namespace
         * @param {string}    name      - The type short name
         * @returns {MonoClass} The MonoClass if the given namespace and name were found, or NULL if it was not found. The error object will contain information about the problem in that case.
         */
        MonoClass.fromNameCaseChecked = function (image, namespace, name) {
            var errPtr = Memory.alloc(Process.pointerSize);
            var classAddress = mono_class_from_name_case_checked(image.$address, Memory.allocUtf8String(namespace), Memory.allocUtf8String(name), errPtr);
            if (classAddress.isNull() || !errPtr.isNull()) {
                throw new Error('Error handling not implemented!');
            }
            return MonoClass.fromAddress(classAddress);
        };
        /**
         * This returns a MonoClass for the specified MonoType, the value is never NULL.
         * @param {MonoType} monoType     - The MonoImage where the type is looked up in
         * @returns {MonoClass} A MonoClass for the specified MonoType, the value is never NULL.
         */
        MonoClass.fromMonoType = function (monoType) {
            //TODO: any must be MonoType which is not implemented atm
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
        MonoClass.fromGenericParameter = function (param /*MonoGenericParam*/) {
            // MonoClass* mono_class_from_generic_parameter (MonoGenericParam *param, MonoImage *arg2 G_GNUC_UNUSED, gboolean arg3 G_GNUC_UNUSED)
            throw new Error('MonoClass.fromGenericParameter is not implemented!');
        };
        MonoClass.fromAddress = function (address) {
            if (address.isNull())
                return null;
            var addressNumber = address.toInt32();
            if (cache$3[addressNumber] === undefined) {
                cache$3[addressNumber] = new MonoClass({ address: address });
            }
            return cache$3[addressNumber];
        };
        return MonoClass;
    }());

    var assemblyCSharp = MonoImage.loaded('Assembly-CSharp');
    var UserMessageManager = MonoClass.fromName(assemblyCSharp, '', 'UserMessageManager');
    console.log(UserMessageManager);

})));
