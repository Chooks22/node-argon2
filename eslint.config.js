import chooks from 'chooks-eslint-config'

export default chooks({
  typescript: {
    parserOptions: {
      projectService: true,
    },
    overrides: {
      'ts/consistent-type-definitions': 'off',
    },
  },
})
