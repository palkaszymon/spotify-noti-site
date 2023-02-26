module.exports = {
  mode: 'jit',
  content: ["./templates/**/*.{html,htm}",
  "./node_modules/flowbite/**/*.js"],
  theme: {
    extend: {},
    fontFamily: {
      'Raleway': ["Raleway", 'sans-serif']
    },
    variants: {
      outline: ["focus"],
    },
  },
}