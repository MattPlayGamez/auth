export default {
    transform: {},
    globals: {
      'ts-jest': {
        useESM: true,
      },
    },
    moduleNameMapper: {
      '^(\\.{1,2}/.*)\\.js$': '$1',  // Use this if you need to handle file extensions in imports
    },
  };
  