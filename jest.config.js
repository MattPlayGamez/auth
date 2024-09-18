export default {
    transform: {},
    extensionsToTreatAsEsm: ['.js'],  // Treat .js files as ESM
    globals: {
        'ts-jest': {
            useESM: true,
        },
    },
    moduleNameMapper: {
        '^(\\.{1,2}/.*)\\.js$': '$1',  // Use this if you have file extensions in imports
    },
};
