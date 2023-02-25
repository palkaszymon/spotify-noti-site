module.exports = {
  mode: 'jit',
  content: ["./templates/**/*.{html,htm}",
  "./node_modules/flowbite/**/*.js"],
  theme: {
    extend: {},
    fontFamily: {
      'Raleway': ["Raleway", 'sans-serif']
    }
  },
  plugins: [require("flowbite/plugin")],
}