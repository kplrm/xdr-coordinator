// Keep backend diagnostics useful without logging event contents or field-value previews.
export function summarizeBulkFailures(items: any[]): string {
  return JSON.stringify(items.slice(0, 3).map((item) => {
    const action = item.index || item.create || item.update || item.delete;
    const causes: string[] = [];
    let field: string | undefined;
    let error = action?.error;
    for (let depth = 0; error && depth < 5; depth++, error = error.caused_by) {
      if (typeof error.type === 'string') causes.push(error.type.slice(0, 80));
      if (typeof error.reason === 'string') {
        const match = /field \[([^\]]+)\]|field="([^"]+)"/.exec(error.reason);
        field = field || match?.[1] || match?.[2];
      }
    }
    return { status: action?.status, field: field?.slice(0, 256), causes };
  }));
}
