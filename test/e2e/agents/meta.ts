import Mono, { type Class } from '../../../src'

const NS = 'FridaMono.Tests'

function required<T>(value: T | null, what: string): T {
  if (value === null) throw new Error(`${what} not found`)
  return value
}

function cls(name: string): Class {
  return Mono.class(`${NS}.${name}`)
}

function describe(klass: Class) {
  return {
    ...klass.toJSON(),
    sealed: klass.isSealed,
    abstract: klass.isAbstract,
    interfaces: klass.interfaces.map(String),
    nested: klass.nestedClasses.map(String),
    declaringClass: klass.declaringClass?.fullName ?? null,
    genericDefinition: klass.isGenericDefinition,
    genericInstance: klass.isGenericInstance,
    fields: klass.fields.map((f) => f.toJSON()),
    methods: klass.methods.map((m) => m.toJSON()),
    properties: klass.properties.map((p) => p.toJSON()),
    events: klass.events.map((e) => e.toJSON())
  }
}

rpc.exports = {
  assembly() {
    return Mono.performNow(() => {
      const assembly = Mono.assembly('TestLib')
      return { ...assembly.toJSON(), image: assembly.image.name, classes: assembly.image.classes.map(String) }
    })
  },

  describe(name: string) {
    return Mono.performNow(() => describe(cls(name)))
  },

  lookups() {
    return Mono.performNow(() => {
      const dog = cls('Dog')
      const animal = cls('Animal')
      return {
        bySimpleName: Mono.findClass('Dog')?.fullName ?? null,
        nestedPlus: Mono.findClass(`${NS}.Dog+Collar`)?.fullName ?? null,
        nestedSlash: Mono.findClass(`${NS}.Dog/Collar`)?.fullName ?? null,
        missing: Mono.findClass(`${NS}.Nope`),
        corlib: Mono.class('System.String').image.name,
        inherited: dog.method('Create')?.fullName ?? null,
        inheritedField: dog.field('Legs')?.class.fullName ?? null,
        inheritedProperty: dog.property('Name')?.class.fullName ?? null,
        inheritedEvent: dog.event('Renamed')?.class.fullName ?? null,
        speakOverloads: dog.methodsNamed('Speak').map(String),
        pickOneParam: cls('Overloads').method('Pick', 2)?.fullName ?? null,
        isSubclass: dog.isSubclassOf(animal),
        implements: dog.isSubclassOf(cls('IGreeter'), true),
        assignable: animal.isAssignableFrom(dog),
        notAssignable: dog.isAssignableFrom(animal),
        hierarchy: dog.hierarchy.map(String),
        byDesc: Mono.findMethod(`${NS}.Overloads:Pick(int,int)`)?.toJSON() ?? null,
        byDescMissing: Mono.findMethod(`${NS}.Overloads:Pick(bool)`)
      }
    })
  },

  types() {
    return Mono.performNow(() => {
      const holder = cls('Holder')
      const type = (field: string) => {
        const t = required(holder.field(field), 'field').type
        return { ...t.toJSON(), class: t.class.fullName, genericInstance: t.class.isGenericInstance, rank: t.class.rank, valueType: t.class.isValueType }
      }
      const access = cls('Access')
      const point = cls('Point')
      return {
        names: type('Names'),
        intBox: type('IntBox'),
        numbers: type('Numbers'),
        origin: type('Origin'),
        numbersElement: required(holder.field('Numbers'), 'field').type.class.elementClass.fullName,
        accessBase: access.enumBaseType?.name ?? null,
        colorBase: cls('Color').enumBaseType?.name ?? null,
        pointSize: point.valueSize,
        swap: required(cls('Overloads').method('Swap'), 'Swap').parameters.map((p) => ({ name: p.name, type: p.type.name, byRef: p.byRef, out: p.out })),
        tryDouble: required(cls('Overloads').method('TryDouble'), 'TryDouble').parameters.map((p) => ({ name: p.name, byRef: p.byRef, out: p.out })),
        mapReturn: required(cls('Box`1').method('Map'), 'Map').returnType.toJSON(),
        boxValue: required(cls('Box`1').field('Value'), 'Value').type.toJSON(),
        interned: Mono.class('System.String') === Mono.class('System.String') && cls('Dog').parent === cls('Animal')
      }
    })
  },

  everything() {
    // Walks all metadata of every loaded assembly; must not crash or throw.
    return Mono.performNow(() => {
      let classes = 0
      let members = 0
      for (const assembly of Mono.assemblies) {
        for (const klass of assembly.image.classes) {
          classes++
          void klass.fullName
          for (const m of klass.methods) {
            members++
            void m.parameters.map((p) => p.type.name)
            void m.returnType.name
          }
          for (const f of klass.fields) {
            members++
            void f.type.name
          }
          members += klass.properties.length + klass.events.length
        }
      }
      return { classes, members }
    })
  }
}
