export const EXAMPLE_RECIPES = [
    {
        name: "PII Scrubber",
        description: "Removes common personal identifiers like emails and UUIDs.",
        steps: [
            { id: "ex_1", type: "email", enabled: true, config: {} },
            { id: "ex_2", type: "uuid", enabled: true, config: {} }
        ]
    },
    {
        name: "Infrastructure Logs",
        description: "Cleans up IP addresses and MAC addresses from server logs.",
        steps: [
            { id: "ex_3", type: "ipv4", enabled: true, config: {} },
            { id: "ex_4", type: "mac", enabled: true, config: {} } // Assuming 'mac' is a valid type or will be
        ]
    },
    {
        name: "API Trace Cleaner",
        description: "Redacts JWTs and UUIDs from API request/response traces.",
        steps: [
            { id: "ex_5", type: "jwt", enabled: true, config: { partial: true } },
            { id: "ex_6", type: "uuid", enabled: true, config: {} }
        ]
    }
];
