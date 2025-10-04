export interface NpmLsNode {
    version?: string;
    // npm ls often omits `name` on child nodes; rely on object keys in `dependencies`
    dependencies?: Record<string, NpmLsNode>;
};

export interface NpmLsTree {
    name?: string;
    version?: string;
    dependencies?: Record<string, NpmLsNode>;
};
