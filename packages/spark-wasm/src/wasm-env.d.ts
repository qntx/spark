/** Minimal ambient WebAssembly declarations for runtimes typed without the DOM lib. */
type BufferSource = ArrayBuffer | ArrayBufferView;

declare namespace WebAssembly {
  type ImportExportKind = "function" | "table" | "memory" | "global";
  type ExportValue = ((...args: number[]) => unknown) | Memory;
  type Exports = Record<string, ExportValue>;
  type ModuleImportDescriptor = {
    module: string;
    name: string;
    kind: ImportExportKind;
  };
  type ModuleExportDescriptor = {
    name: string;
    kind: ImportExportKind;
  };

  interface Memory {
    readonly buffer: ArrayBuffer;
  }

  type Module = { readonly kind: "module" };

  interface Instance {
    readonly exports: Exports;
  }

  interface RuntimeError extends Error {
    name: "RuntimeError";
  }

  var Memory: new (descriptor: { initial: number; maximum?: number }) => Memory;

  var Module: {
    new (bytes: BufferSource): Module;
    imports: (module: Module) => ModuleImportDescriptor[];
    exports: (module: Module) => ModuleExportDescriptor[];
  };

  var Instance: new (
    module: Module,
    importObject?: Record<string, Record<string, ExportValue>>,
  ) => Instance;

  var RuntimeError: new (message?: string) => RuntimeError;

  var CompileError: new (message?: string) => Error;

  var compile: (bytes: BufferSource | Module) => Promise<Module>;

  var instantiate: {
    (bytes: BufferSource): Promise<{ module: Module; instance: Instance }>;
    (module: Module, importObject?: Record<string, Record<string, ExportValue>>): Promise<Instance>;
  };
}
