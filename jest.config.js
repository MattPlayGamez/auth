export default {
    transform: {
        "^.+\\.js$": "babel-jest",  // Use Babel to transform JavaScript files
    },
    globals: {
        'ts-jest': {
            useESM: true,
        },
    },
    moduleNameMapper: {
        '^(\\.{1,2}/.*)\\.js$': '$1',  // Adjust for file extensions in imports
    },
};
