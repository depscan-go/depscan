package model

type Dependency struct {
	Ecosystem string
	Name      string
	Version   string
	Direct    bool
	License   string
}

type Finding struct {
	Dep          Dependency
	VulnID       string
	Aliases      []string
	Severity     string
	Summary      string
	FixedVersion string
}

type Violation struct {
	Kind   string
	Dep    Dependency
	Reason string
}

type ScanResult struct {
	Deps       []Dependency
	Findings   []Finding
	Violations []Violation
	Warnings   []Violation
}
