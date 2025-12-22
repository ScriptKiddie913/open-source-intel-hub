import { useState, useCallback } from "react";
import { Upload, FileText, Database, AlertCircle, CheckCircle2, X, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { 
  parseCSVFile, 
  parseJSONFile, 
  parseTXTFile, 
  detectFileFormat, 
  validateBreachData, 
  normalizeBreachData,
  normalizeDomainList,
  normalizeIPList,
  ValidationResult,
} from "@/lib/dataParser";
import { importBreaches, saveDataset, getDatasets, logActivity } from "@/lib/database";
import { useToast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";
import { ImportedDataset } from "@/types/osint";

type ImportType = "breach" | "domains" | "ips" | "keywords";

export function DataImporter() {
  const [dragActive, setDragActive] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [importType, setImportType] = useState<ImportType>("breach");
  const [preview, setPreview] = useState<any[] | null>(null);
  const [validation, setValidation] = useState<ValidationResult | null>(null);
  const [importing, setImporting] = useState(false);
  const [datasets, setDatasets] = useState<ImportedDataset[]>([]);
  const { toast } = useToast();

  const loadDatasets = useCallback(async () => {
    const data = await getDatasets();
    setDatasets(data);
  }, []);

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    
    const files = e.dataTransfer.files;
    if (files && files[0]) {
      await handleFile(files[0]);
    }
  };

  const handleFileInput = async (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      await handleFile(e.target.files[0]);
    }
  };

  const handleFile = async (file: File) => {
    const format = detectFileFormat(file);
    
    if (format === "unknown") {
      toast({ 
        title: "Unsupported format", 
        description: "Please upload CSV, JSON, or TXT files", 
        variant: "destructive" 
      });
      return;
    }

    setSelectedFile(file);
    
    try {
      let data: any[];
      
      if (format === "csv") {
        data = await parseCSVFile(file);
      } else if (format === "json") {
        data = await parseJSONFile(file);
      } else {
        const lines = await parseTXTFile(file);
        data = lines.map((line, i) => ({ value: line, _rowIndex: i }));
      }

      // Show preview (first 10 rows)
      setPreview(data.slice(0, 10));

      // Validate if breach data
      if (importType === "breach") {
        const validationResult = validateBreachData(data);
        setValidation(validationResult);
      } else {
        setValidation({ 
          valid: true, 
          errors: [], 
          warnings: [], 
          stats: { totalRows: data.length, validRows: data.length, invalidRows: 0 } 
        });
      }
    } catch (error) {
      console.error("Parse error:", error);
      toast({ title: "Parse error", description: "Failed to parse file", variant: "destructive" });
    }
  };

  const handleImport = async () => {
    if (!selectedFile || !preview) return;

    setImporting(true);

    try {
      let data: any[];
      const format = detectFileFormat(selectedFile);

      if (format === "csv") {
        data = await parseCSVFile(selectedFile);
      } else if (format === "json") {
        data = await parseJSONFile(selectedFile);
      } else {
        data = await parseTXTFile(selectedFile);
      }

      let recordCount = 0;

      if (importType === "breach") {
        const breaches = normalizeBreachData(data, selectedFile.name);
        await importBreaches(breaches);
        recordCount = breaches.length;
      } else if (importType === "domains") {
        const domains = normalizeDomainList(data as string[]);
        recordCount = domains.length;
        // Store in IndexedDB as records
      } else if (importType === "ips") {
        const ips = normalizeIPList(data as string[]);
        recordCount = ips.length;
      }

      // Save dataset metadata
      await saveDataset({
        id: crypto.randomUUID(),
        name: selectedFile.name,
        type: importType,
        recordCount,
        importedAt: new Date(),
        size: selectedFile.size,
      });

      await logActivity({
        type: "upload",
        title: `Imported ${selectedFile.name}`,
        description: `${recordCount} records added to ${importType} database`,
      });

      toast({ title: "Import complete", description: `${recordCount} records imported` });
      
      // Reset state
      setSelectedFile(null);
      setPreview(null);
      setValidation(null);
      await loadDatasets();
    } catch (error) {
      console.error("Import error:", error);
      toast({ title: "Import failed", description: "An error occurred", variant: "destructive" });
    } finally {
      setImporting(false);
    }
  };

  const formatFileSize = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-foreground">Import Data</h1>
        <p className="text-muted-foreground text-sm mt-1">
          Upload breach databases, domain lists, IP ranges, or keyword lists
        </p>
      </div>

      {/* Import Type Selection */}
      <div className="card-cyber p-4">
        <p className="text-sm font-medium text-foreground mb-3">Data Type</p>
        <div className="flex flex-wrap gap-2">
          {[
            { value: "breach", label: "Breach Database", icon: Database },
            { value: "domains", label: "Domain List", icon: FileText },
            { value: "ips", label: "IP Addresses", icon: FileText },
            { value: "keywords", label: "Keywords", icon: FileText },
          ].map((type) => (
            <button
              key={type.value}
              onClick={() => setImportType(type.value as ImportType)}
              className={cn(
                "flex items-center gap-2 px-4 py-2 rounded-lg border transition-all",
                importType === type.value
                  ? "bg-primary/10 border-primary text-primary"
                  : "border-border text-muted-foreground hover:border-primary/50 hover:text-foreground"
              )}
            >
              <type.icon className="h-4 w-4" />
              <span className="text-sm font-medium">{type.label}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Upload Zone */}
      <div
        onDragEnter={handleDrag}
        onDragLeave={handleDrag}
        onDragOver={handleDrag}
        onDrop={handleDrop}
        className={cn(
          "card-cyber p-8 border-2 border-dashed transition-all cursor-pointer",
          dragActive ? "border-primary bg-primary/5" : "border-border hover:border-primary/50"
        )}
      >
        <input
          type="file"
          id="file-upload"
          accept=".csv,.json,.txt"
          onChange={handleFileInput}
          className="hidden"
        />
        <label htmlFor="file-upload" className="cursor-pointer">
          <div className="flex flex-col items-center text-center">
            <div className={cn(
              "p-4 rounded-full mb-4 transition-colors",
              dragActive ? "bg-primary/20" : "bg-secondary"
            )}>
              <Upload className={cn(
                "h-8 w-8 transition-colors",
                dragActive ? "text-primary" : "text-muted-foreground"
              )} />
            </div>
            <p className="text-foreground font-medium mb-1">
              {dragActive ? "Drop file here" : "Drag & drop or click to upload"}
            </p>
            <p className="text-sm text-muted-foreground">
              Supports CSV, JSON, and TXT files
            </p>
          </div>
        </label>
      </div>

      {/* Selected File */}
      {selectedFile && (
        <div className="card-cyber p-4 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <FileText className="h-5 w-5 text-primary" />
              <div>
                <p className="font-medium text-foreground">{selectedFile.name}</p>
                <p className="text-xs text-muted-foreground">
                  {formatFileSize(selectedFile.size)} • {detectFileFormat(selectedFile).toUpperCase()}
                </p>
              </div>
            </div>
            <Button
              variant="ghost"
              size="icon"
              onClick={() => {
                setSelectedFile(null);
                setPreview(null);
                setValidation(null);
              }}
            >
              <X className="h-4 w-4" />
            </Button>
          </div>

          {/* Validation */}
          {validation && (
            <div className={cn(
              "p-3 rounded-lg flex items-start gap-3",
              validation.valid ? "bg-success/10 border border-success/30" : "bg-destructive/10 border border-destructive/30"
            )}>
              {validation.valid ? (
                <CheckCircle2 className="h-5 w-5 text-success mt-0.5" />
              ) : (
                <AlertCircle className="h-5 w-5 text-destructive mt-0.5" />
              )}
              <div>
                <p className={cn("font-medium", validation.valid ? "text-success" : "text-destructive")}>
                  {validation.valid ? "Validation passed" : "Validation failed"}
                </p>
                <p className="text-sm text-muted-foreground mt-1">
                  {validation.stats.totalRows} rows • {validation.stats.validRows} valid • {validation.stats.invalidRows} invalid
                </p>
                {validation.errors.length > 0 && (
                  <ul className="text-sm text-destructive mt-2 list-disc list-inside">
                    {validation.errors.map((error, i) => (
                      <li key={i}>{error}</li>
                    ))}
                  </ul>
                )}
                {validation.warnings.length > 0 && (
                  <ul className="text-sm text-warning mt-2 list-disc list-inside">
                    {validation.warnings.slice(0, 3).map((warning, i) => (
                      <li key={i}>{warning}</li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
          )}

          {/* Preview */}
          {preview && preview.length > 0 && (
            <div>
              <p className="text-sm font-medium text-foreground mb-2">Preview (first 10 rows)</p>
              <div className="overflow-x-auto max-h-48 overflow-y-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-border bg-secondary/50">
                      {Object.keys(preview[0]).filter(k => k !== "_rowIndex").map((key) => (
                        <th key={key} className="text-left p-2 font-semibold text-muted-foreground uppercase">
                          {key}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {preview.map((row, i) => (
                      <tr key={i} className="border-b border-border/50">
                        {Object.entries(row).filter(([k]) => k !== "_rowIndex").map(([key, value]) => (
                          <td key={key} className="p-2 font-mono text-foreground max-w-xs truncate">
                            {String(value)}
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Import Button */}
          <Button
            onClick={handleImport}
            disabled={!validation?.valid || importing}
            variant="cyber"
            className="w-full"
          >
            {importing ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin mr-2" />
                Importing...
              </>
            ) : (
              <>
                <Database className="h-4 w-4 mr-2" />
                Import {validation?.stats.validRows || 0} Records
              </>
            )}
          </Button>
        </div>
      )}

      {/* Imported Datasets */}
      <div className="card-cyber p-4">
        <h2 className="font-semibold text-foreground mb-4">Imported Datasets</h2>
        {datasets.length > 0 ? (
          <div className="space-y-2">
            {datasets.map((dataset) => (
              <div
                key={dataset.id}
                className="flex items-center justify-between p-3 rounded-lg bg-secondary/50"
              >
                <div className="flex items-center gap-3">
                  <Database className="h-4 w-4 text-primary" />
                  <div>
                    <p className="font-medium text-foreground text-sm">{dataset.name}</p>
                    <p className="text-xs text-muted-foreground">
                      {dataset.recordCount.toLocaleString()} records • {dataset.type} • {formatFileSize(dataset.size)}
                    </p>
                  </div>
                </div>
                <span className="text-xs text-muted-foreground font-mono">
                  {new Date(dataset.importedAt).toLocaleDateString()}
                </span>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-sm text-muted-foreground text-center py-4">
            No datasets imported yet
          </p>
        )}
      </div>
    </div>
  );
}
