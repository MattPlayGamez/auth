export default {
    transform: {
        "^.+\\.js$": "babel-jest",  // Use babel-jest for JavaScript files
    },
    moduleNameMapper: {
        '^(\\.{1,2}/.*)\\.js$': '$1',  // Handle imports without file extensions
    },
};
