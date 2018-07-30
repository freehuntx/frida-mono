const FridaInject = require('frida-inject')

FridaInject({
  debug: true,
  name: 'UltimateChickenHorse.exe',
  scripts: [
    './src'
  ]
})
