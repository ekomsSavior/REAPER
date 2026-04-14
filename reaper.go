package main

import (
    "bufio"
    "bytes"
    "context"
    "crypto/sha256"
    "encoding/base64"
    "encoding/csv"
    "encoding/hex"
    "encoding/json"
    "flag"
    "fmt"
    "log"
    "math"
    "net/http"
    "os"
    "os/signal"
    "path/filepath"
    "regexp"
    "strings"
    "sync"
    "syscall"
    "time"
    
    "github.com/google/go-github/v61/github"
    "golang.org/x/oauth2"
    "golang.org/x/time/rate"
)

// Configuration flags
var (
    githubToken      = flag.String("token", "", "GitHub Personal Access Token (or set GITHUB_TOKEN env)")
    outputDir        = flag.String("output", "./output", "Output directory for findings")
    workers          = flag.Int("workers", 20, "Number of concurrent workers")
    minStars         = flag.Int("min-stars", 0, "Minimum stars filter")
    sinceDays        = flag.Int("since-days", 7, "Only scan repos updated in last X days (repeats)")
    verbose          = flag.Bool("verbose", false, "Verbose output")
    scanPRs          = flag.Bool("scan-prs", true, "Scan pull requests")
    scanIssues       = flag.Bool("scan-issues", true, "Scan issues and comments")
    scanCommits      = flag.Bool("scan-commits", true, "Scan commit history")
    entropyCheck     = flag.Bool("entropy", true, "Enable entropy checking")
    continuous       = flag.Bool("continuous", true, "Run continuously (loop forever)")
    sleepMinutes     = flag.Int("sleep-minutes", 60, "Sleep between continuous cycles")
    scanAdvisories   = flag.Bool("scan-advisories", false, "Check repository for GitHub Security Advisories (requires additional API calls)")
    hideObfuscated   = flag.Bool("hide-obfuscated", true, "Hide obfuscated emails (e.g., user[at]example[dot]com)")
    
    // Single/multiple repo scanning
    repoURLs         = flag.String("repo", "", "Single repository URL to scan (can be used multiple times)")
    repoListFile     = flag.String("repo-list", "", "File containing repository URLs (one per line)")
)

// Core types
type Reaper struct {
    client          *github.Client
    patterns        []*SecretPattern
    results         chan *Finding
    advisories      chan *Advisory
    limiter         *rate.Limiter
    ctx             context.Context
    cancel          context.CancelFunc
    wg              sync.WaitGroup
    stats           *ScanStats
    csvWriter       *csv.Writer
    jsonFile        *os.File
    advFile         *os.File
    mu              sync.Mutex
    scannedRepos    map[string]bool
    emailCache      map[string]map[string]bool // repo -> email -> found
}

type SecretPattern struct {
    Name     string
    Regex    *regexp.Regexp
    Severity string
    Entropy  bool
}

type Finding struct {
    ID          string    `json:"id"`
    Repository  string    `json:"repository"`
    FilePath    string    `json:"file_path"`
    LineNumber  int       `json:"line_number"`
    SecretType  string    `json:"secret_type"`
    SecretValue string    `json:"secret_value"`
    Context     string    `json:"context"`
    URL         string    `json:"url"`
    Branch      string    `json:"branch"`
    Timestamp   time.Time `json:"timestamp"`
    Severity    string    `json:"severity"`
}

type Advisory struct {
    ID                 string    `json:"id"`
    Repository         string    `json:"repository"`
    GHSAID             string    `json:"ghsa_id"`
    CVEID              string    `json:"cve_id,omitempty"`
    Summary            string    `json:"summary"`
    Severity           string    `json:"severity"`
    PublishedAt        time.Time `json:"published_at"`
    UpdatedAt          time.Time `json:"updated_at"`
    Permalink          string    `json:"permalink"`
    VulnerableManifest string    `json:"vulnerable_manifest,omitempty"`
}

type ScanStats struct {
    ReposScanned    int
    FilesScanned    int
    FindingsFound   int
    AdvisoriesFound int
    StartTime       time.Time
    CycleStart      time.Time
    RateLimitHits   int
    mu              sync.Mutex
}

func main() {
    flag.Parse()
    
    token := *githubToken
    if token == "" {
        token = os.Getenv("GITHUB_TOKEN")
    }
    if token == "" {
        log.Fatal("GitHub token required. Use -token flag or GITHUB_TOKEN env variable")
    }
    
    if err := os.MkdirAll(*outputDir, 0755); err != nil {
        log.Fatalf("Failed to create output directory: %v", err)
    }
    
    reaper := NewReaper(token)
    
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
    go func() {
        <-sigChan
        fmt.Println("\nShutting down REAPER gracefully...")
        reaper.cancel()
    }()
    
    fmt.Println(`
    ============================================================
    ██████╗ ███████╗ █████╗ ██████╗ ███████╗██████╗ 
    ██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗
    ██████╔╝█████╗  ███████║██████╔╝█████╗  ██████╔╝
    ██╔══██╗██╔══╝  ██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗
    ██║  ██║███████╗██║  ██║██║     ███████╗██║  ██║
    ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝
    ============================================================
    REAPER - GitHub Secret Harvester & Advisory Scanner
    ============================================================
    `)
    
    // Determine mode: single-shot or continuous
    targetRepos := getTargetRepos()
    if len(targetRepos) > 0 {
        fmt.Printf("[!] Single-shot mode: scanning %d specific repository(s)\n", len(targetRepos))
        fmt.Printf("[+] Output directory: %s\n", *outputDir)
        fmt.Printf("[+] Scan commits: %v\n", *scanCommits)
        fmt.Printf("[+] Scan advisories: %v\n", *scanAdvisories)
        fmt.Printf("[+] Hide obfuscated emails: %v\n", *hideObfuscated)
        
        for _, repoURL := range targetRepos {
            repo, err := reaper.getRepoFromURL(repoURL)
            if err != nil {
                log.Printf("Failed to parse %s: %v", repoURL, err)
                continue
            }
            reaper.scanRepository(repo)
            reaper.stats.mu.Lock()
            reaper.stats.ReposScanned++
            reaper.stats.mu.Unlock()
        }
        reaper.printFinalStats()
        return
    }
    
    // Normal continuous mode
    fmt.Printf("[+] Starting REAPER with %d workers\n", *workers)
    fmt.Printf("[+] Output directory: %s\n", *outputDir)
    fmt.Printf("[+] Continuous mode: %v (sleep %d min between cycles)\n", *continuous, *sleepMinutes)
    fmt.Printf("[+] Scanning repos updated in last %d days\n", *sinceDays)
    fmt.Printf("[+] Scan commits: %v\n", *scanCommits)
    fmt.Printf("[+] Scan advisories: %v\n", *scanAdvisories)
    fmt.Printf("[+] Hide obfuscated emails: %v\n", *hideObfuscated)
    
    reaper.RunForever()
}

func getTargetRepos() []string {
    var repos []string
    
    flag.Visit(func(f *flag.Flag) {
        if f.Name == "repo" && f.Value.String() != "" {
            repos = append(repos, f.Value.String())
        }
    })
    
    if *repoListFile != "" {
        file, err := os.Open(*repoListFile)
        if err == nil {
            defer file.Close()
            scanner := bufio.NewScanner(file)
            for scanner.Scan() {
                line := strings.TrimSpace(scanner.Text())
                if line != "" && !strings.HasPrefix(line, "#") {
                    repos = append(repos, line)
                }
            }
        } else {
            log.Printf("Warning: could not open repo list file %s: %v", *repoListFile, err)
        }
    }
    
    return repos
}

func (r *Reaper) getRepoFromURL(rawURL string) (*github.Repository, error) {
    rawURL = strings.TrimSuffix(rawURL, ".git")
    parts := strings.Split(strings.TrimPrefix(rawURL, "https://github.com/"), "/")
    if len(parts) < 2 {
        return nil, fmt.Errorf("invalid repository URL: %s", rawURL)
    }
    owner, name := parts[0], parts[1]
    
    repo, _, err := r.client.Repositories.Get(r.ctx, owner, name)
    return repo, err
}

func NewReaper(token string) *Reaper {
    ctx, cancel := context.WithCancel(context.Background())
    
    ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
    tc := oauth2.NewClient(ctx, ts)
    client := github.NewClient(tc)
    
    jsonFile, _ := os.OpenFile(filepath.Join(*outputDir, "reaper_findings.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    advFile, _ := os.OpenFile(filepath.Join(*outputDir, "advisories.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    
    timestamp := time.Now().Format("20060102_150405")
    csvFile, _ := os.Create(filepath.Join(*outputDir, fmt.Sprintf("reaper_findings_%s.csv", timestamp)))
    csvWriter := csv.NewWriter(csvFile)
    csvWriter.Write([]string{"Timestamp", "Repository", "File", "Line", "Type", "Secret", "URL", "Severity"})
    
    scannedRepos := make(map[string]bool)
    scannedFile, err := os.OpenFile(filepath.Join(*outputDir, "scanned_repos.txt"), os.O_RDWR|os.O_CREATE, 0644)
    if err == nil {
        scanner := bufio.NewScanner(scannedFile)
        for scanner.Scan() {
            scannedRepos[scanner.Text()] = true
        }
        scannedFile.Close()
    }
    
    reaper := &Reaper{
        client:       client,
        patterns:     GetAllPatterns(),
        results:      make(chan *Finding, 10000),
        advisories:   make(chan *Advisory, 1000),
        limiter:      rate.NewLimiter(rate.Limit(30), 100),
        ctx:          ctx,
        cancel:       cancel,
        stats:        &ScanStats{StartTime: time.Now()},
        csvWriter:    csvWriter,
        jsonFile:     jsonFile,
        advFile:      advFile,
        scannedRepos: scannedRepos,
        emailCache:   make(map[string]map[string]bool),
    }
    
    go reaper.processResults()
    go reaper.processAdvisories()
    
    return reaper
}

// isObfuscatedEmail checks if an email address is obfuscated
func isObfuscatedEmail(email string) bool {
    obfuscatedPatterns := []string{
        "[at]", "[@]", "{at}", "{@}",
        " at ", "(at)", "[dot]", "{dot}", "(dot)",
        " dot ", " DOT ", " AT ",
        " user@", "@domain", "example.com",
        "replace@", "change@", "obfuscated",
        "noreply", "no-reply", "do-not-reply",
    }
    emailLower := strings.ToLower(email)
    for _, pattern := range obfuscatedPatterns {
        if strings.Contains(emailLower, pattern) {
            return true
        }
    }
    // Check for invalid domain patterns
    if strings.Contains(email, "@[") && strings.Contains(email, "]") {
        return true
    }
    if strings.Contains(email, "@(") && strings.Contains(email, ")") {
        return true
    }
    // Check for placeholder domains
    placeholderDomains := []string{"example.com", "domain.com", "test.com", "localhost", "invalid"}
    for _, domain := range placeholderDomains {
        if strings.Contains(emailLower, "@"+domain) {
            return true
        }
    }
    return false
}

// isGitHubNoReply checks for GitHub's no-reply emails
func isGitHubNoReply(email string) bool {
    return strings.Contains(email, "noreply.github.com") || strings.Contains(email, "users.noreply.github.com")
}

func (r *Reaper) isDuplicateEmail(repoName, email string) bool {
    r.mu.Lock()
    defer r.mu.Unlock()
    
    if _, exists := r.emailCache[repoName]; !exists {
        r.emailCache[repoName] = make(map[string]bool)
    }
    
    if r.emailCache[repoName][email] {
        return true
    }
    
    r.emailCache[repoName][email] = true
    return false
}

func GetAllPatterns() []*SecretPattern {
    return []*SecretPattern{
        {Name: "AWS Access Key", Regex: regexp.MustCompile(`AKIA[0-9A-Z]{16}`), Severity: "CRITICAL", Entropy: false},
        {Name: "AWS Secret Key", Regex: regexp.MustCompile(`(?i)(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[:=\s]+['"]?([A-Za-z0-9/+=]{40})['"]?`), Severity: "CRITICAL", Entropy: true},
        {Name: "Google API Key", Regex: regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`), Severity: "CRITICAL", Entropy: false},
        {Name: "GitHub Token", Regex: regexp.MustCompile(`ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}`), Severity: "CRITICAL", Entropy: false},
        {Name: "Slack Token", Regex: regexp.MustCompile(`xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}`), Severity: "HIGH", Entropy: false},
        {Name: "Discord Bot Token", Regex: regexp.MustCompile(`[MNO][a-zA-Z\d_-]{23,25}\.[a-zA-Z\d_-]{6}\.[a-zA-Z\d_-]{27}`), Severity: "CRITICAL", Entropy: false},
        {Name: "Stripe Secret Key", Regex: regexp.MustCompile(`sk_live_[A-Za-z0-9]{24}`), Severity: "CRITICAL", Entropy: false},
        {Name: "Stripe Publishable Key", Regex: regexp.MustCompile(`pk_live_[A-Za-z0-9]{24}`), Severity: "HIGH", Entropy: false},
        {Name: "JWT Token", Regex: regexp.MustCompile(`eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*`), Severity: "HIGH", Entropy: true},
        {Name: "PostgreSQL URL", Regex: regexp.MustCompile(`postgresql://[^/\s]+:[^/\s]+@[^/\s]+/\w+`), Severity: "CRITICAL", Entropy: false},
        {Name: "MySQL URL", Regex: regexp.MustCompile(`mysql://[^/\s]+:[^/\s]+@[^/\s]+/\w+`), Severity: "CRITICAL", Entropy: false},
        {Name: "MongoDB URL", Regex: regexp.MustCompile(`mongodb(?:\+srv)?://[^/\s]+:[^/\s]+@[^/\s]+/\w+`), Severity: "CRITICAL", Entropy: false},
        {Name: "Redis URL", Regex: regexp.MustCompile(`redis://(?:[^:@]+:[^@]+@)?[^:]+:[0-9]+`), Severity: "HIGH", Entropy: false},
        {Name: "RSA Private Key", Regex: regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`), Severity: "CRITICAL", Entropy: false},
        {Name: "SSH Private Key", Regex: regexp.MustCompile(`-----BEGIN OPENSSH PRIVATE KEY-----`), Severity: "CRITICAL", Entropy: false},
        {Name: "EC Private Key", Regex: regexp.MustCompile(`-----BEGIN EC PRIVATE KEY-----`), Severity: "CRITICAL", Entropy: false},
        {Name: "Email Address", Regex: regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`), Severity: "MEDIUM", Entropy: false},
        {Name: "Generic Password", Regex: regexp.MustCompile(`(?i)(?:password|passwd|pwd)\s*[:=\s]+['"]?([^'"\s]{8,50})['"]?`), Severity: "HIGH", Entropy: false},
        {Name: "Generic API Key", Regex: regexp.MustCompile(`(?i)(?:api[_-]?key|apikey|api_token|token)\s*[:=\s]+['"]?([A-Za-z0-9]{20,50})['"]?`), Severity: "HIGH", Entropy: true},
        {Name: "Azure Connection String", Regex: regexp.MustCompile(`DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+`), Severity: "CRITICAL", Entropy: false},
        {Name: "Twilio API Key", Regex: regexp.MustCompile(`SK[0-9a-fA-F]{32}`), Severity: "HIGH", Entropy: false},
        {Name: "SendGrid API Key", Regex: regexp.MustCompile(`SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}`), Severity: "HIGH", Entropy: false},
        {Name: "Heroku API Key", Regex: regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`), Severity: "HIGH", Entropy: true},
        {Name: "OpenAI API Key", Regex: regexp.MustCompile(`sk-[A-Za-z0-9]{48}`), Severity: "CRITICAL", Entropy: true},
        {Name: "Telegram Bot Token", Regex: regexp.MustCompile(`[0-9]{8,10}:[A-Za-z0-9_-]{35}`), Severity: "CRITICAL", Entropy: false},
        {Name: "GitHub App Token", Regex: regexp.MustCompile(`ghu_[A-Za-z0-9]{36}`), Severity: "CRITICAL", Entropy: false},
        {Name: "GitLab Token", Regex: regexp.MustCompile(`glpat-[A-Za-z0-9-_]{20}`), Severity: "HIGH", Entropy: false},
        {Name: "Docker Hub Token", Regex: regexp.MustCompile(`dckr_pat_[A-Za-z0-9-_]{32}`), Severity: "HIGH", Entropy: false},
        {Name: "NPM Token", Regex: regexp.MustCompile(`npm_[A-Za-z0-9]{36}`), Severity: "HIGH", Entropy: false},
        {Name: "Pulumi API Key", Regex: regexp.MustCompile(`pul-[a-f0-9]{40}`), Severity: "HIGH", Entropy: false},
        {Name: "DigitalOcean Token", Regex: regexp.MustCompile(`dops_v1_[a-zA-Z0-9]{64}`), Severity: "HIGH", Entropy: false},
        {Name: "Alibaba Cloud Key", Regex: regexp.MustCompile(`LTAI[A-Za-z0-9]{16,20}`), Severity: "HIGH", Entropy: false},
    }
}

func (r *Reaper) RunForever() {
    for {
        select {
        case <-r.ctx.Done():
            r.printFinalStats()
            return
        default:
        }
        
        fmt.Printf("\nStarting new scan cycle at %s\n", time.Now().Format("15:04:05"))
        r.stats.CycleStart = time.Now()
        
        if err := r.scanCycle(); err != nil {
            log.Printf("Scan cycle error: %v", err)
        }
        
        cycleDuration := time.Since(r.stats.CycleStart)
        r.stats.mu.Lock()
        fmt.Printf("\nCycle complete: %d repos, %d findings, %d advisories in %s\n",
            r.stats.ReposScanned, r.stats.FindingsFound, r.stats.AdvisoriesFound, cycleDuration.Round(time.Second))
        r.stats.mu.Unlock()
        
        if !*continuous {
            break
        }
        
        fmt.Printf("Sleeping for %d minutes before next cycle...\n", *sleepMinutes)
        sleepTimer := time.NewTimer(time.Duration(*sleepMinutes) * time.Minute)
        select {
        case <-sleepTimer.C:
        case <-r.ctx.Done():
            sleepTimer.Stop()
            return
        }
    }
    r.printFinalStats()
}

func (r *Reaper) scanCycle() error {
    query := r.buildSearchQuery()
    fmt.Printf("[+] Search query: %s\n", query)
    
    opts := &github.SearchOptions{
        Sort:        "updated",
        Order:       "desc",
        ListOptions: github.ListOptions{PerPage: 100},
    }
    
    for {
        select {
        case <-r.ctx.Done():
            return nil
        default:
        }
        
        if err := r.limiter.Wait(r.ctx); err != nil {
            return err
        }
        
        result, resp, err := r.client.Search.Repositories(r.ctx, query, opts)
        if err != nil {
            if strings.Contains(err.Error(), "rate limit") {
                r.stats.RateLimitHits++
                time.Sleep(60 * time.Second)
                continue
            }
            return fmt.Errorf("search failed: %w", err)
        }
        
        if len(result.Repositories) == 0 {
            fmt.Println("[+] No new repositories found in this cycle.")
            break
        }
        
        fmt.Printf("[+] Found %d repositories (page %d)\n", len(result.Repositories), opts.Page)
        
        repoChan := make(chan *github.Repository, len(result.Repositories))
        var workerWg sync.WaitGroup
        
        for i := 0; i < *workers; i++ {
            workerWg.Add(1)
            go r.repoWorker(repoChan, &workerWg)
        }
        
        newRepos := 0
        for _, repo := range result.Repositories {
            if repo.GetPrivate() {
                continue
            }
            if *minStars > 0 && repo.GetStargazersCount() < *minStars {
                continue
            }
            
            r.mu.Lock()
            if r.scannedRepos[repo.GetFullName()] {
                r.mu.Unlock()
                continue
            }
            r.scannedRepos[repo.GetFullName()] = true
            r.mu.Unlock()
            
            repoChan <- repo
            newRepos++
        }
        
        close(repoChan)
        workerWg.Wait()
        
        fmt.Printf("[+] Cycle progress: %d new repos scanned, total findings: %d, total advisories: %d\n",
            newRepos, r.stats.FindingsFound, r.stats.AdvisoriesFound)
        
        if resp.NextPage == 0 {
            break
        }
        opts.Page = resp.NextPage
    }
    
    r.saveScannedList()
    return nil
}

func (r *Reaper) repoWorker(repoChan <-chan *github.Repository, wg *sync.WaitGroup) {
    defer wg.Done()
    
    for repo := range repoChan {
        select {
        case <-r.ctx.Done():
            return
        default:
        }
        
        r.scanRepository(repo)
        r.stats.mu.Lock()
        r.stats.ReposScanned++
        r.stats.mu.Unlock()
    }
}

func (r *Reaper) scanRepository(repo *github.Repository) {
    repoName := repo.GetFullName()
    if repo.GetArchived() {
        return
    }
    
    defaultBranch := repo.GetDefaultBranch()
    r.scanBranch(repoName, defaultBranch)
    
    if *scanPRs {
        r.scanPullRequests(repoName)
    }
    if *scanIssues {
        r.scanIssues(repoName)
    }
    if *scanCommits {
        r.scanCommitHistory(repoName, defaultBranch)
    }
    if *scanAdvisories {
        r.fetchAdvisories(repoName, getOwner(repoName), getRepoName(repoName))
    }
}

func (r *Reaper) scanBranch(repoName, branch string) {
    opts := &github.RepositoryContentGetOptions{Ref: branch}
    _, contents, _, err := r.client.Repositories.GetContents(
        r.ctx, getOwner(repoName), getRepoName(repoName), "/", opts)
    if err != nil {
        return
    }
    r.processContents(repoName, branch, contents, opts.Ref)
}

func (r *Reaper) processContents(repoName, branch string, contents []*github.RepositoryContent, ref string) {
    for _, content := range contents {
        select {
        case <-r.ctx.Done():
            return
        default:
        }
        if content == nil {
            continue
        }
        if *content.Type == "dir" {
            _, dirContents, _, err := r.client.Repositories.GetContents(
                r.ctx, getOwner(repoName), getRepoName(repoName), content.GetPath(),
                &github.RepositoryContentGetOptions{Ref: ref})
            if err == nil {
                r.processContents(repoName, branch, dirContents, ref)
            }
        } else if *content.Type == "file" {
            r.scanFile(repoName, branch, content)
        }
    }
}

func (r *Reaper) scanFile(repoName, branch string, file *github.RepositoryContent) {
    ext := strings.ToLower(filepath.Ext(file.GetName()))
    skipExts := map[string]bool{
        ".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".ico": true,
        ".mp4": true, ".mp3": true, ".zip": true, ".tar": true, ".gz": true,
        ".exe": true, ".dll": true, ".so": true, ".bin": true,
    }
    if skipExts[ext] {
        return
    }
    
    content, err := file.GetContent()
    if err != nil {
        return
    }
    decoded, err := base64.StdEncoding.DecodeString(content)
    if err != nil {
        decoded = []byte(content)
    }
    
    r.stats.mu.Lock()
    r.stats.FilesScanned++
    r.stats.mu.Unlock()
    
    lines := strings.Split(string(decoded), "\n")
    for i, line := range lines {
        for _, pattern := range r.patterns {
            matches := pattern.Regex.FindAllStringSubmatch(line, -1)
            if len(matches) == 0 {
                continue
            }
            for _, match := range matches {
                secret := match[0]
                if len(match) > 1 && match[1] != "" {
                    secret = match[1]
                }
                if *entropyCheck && pattern.Entropy && !hasHighEntropy(secret) {
                    continue
                }
                
                // Special handling for Email Addresses
                if pattern.Name == "Email Address" {
                    // Skip obfuscated emails if flag is set
                    if *hideObfuscated && isObfuscatedEmail(secret) {
                        continue
                    }
                    // Skip GitHub no-reply emails
                    if isGitHubNoReply(secret) {
                        continue
                    }
                    // Deduplicate emails per repository
                    if r.isDuplicateEmail(repoName, secret) {
                        continue
                    }
                }
                
                hash := sha256.Sum256([]byte(repoName + file.GetPath() + secret))
                id := hex.EncodeToString(hash[:])[:16]
                
                finding := &Finding{
                    ID:          id,
                    Repository:  repoName,
                    FilePath:    file.GetPath(),
                    LineNumber:  i + 1,
                    SecretType:  pattern.Name,
                    SecretValue: maskSecret(secret),
                    Context:     getContext(lines, i, 2),
                    URL:         file.GetHTMLURL(),
                    Branch:      branch,
                    Timestamp:   time.Now(),
                    Severity:    pattern.Severity,
                }
                r.results <- finding
            }
        }
    }
}

func (r *Reaper) scanPullRequests(repoName string) {
    opts := &github.PullRequestListOptions{State: "all", ListOptions: github.ListOptions{PerPage: 50}}
    for {
        select {
        case <-r.ctx.Done():
            return
        default:
        }
        if err := r.limiter.Wait(r.ctx); err != nil {
            return
        }
        prs, resp, err := r.client.PullRequests.List(r.ctx, getOwner(repoName), getRepoName(repoName), opts)
        if err != nil {
            return
        }
        for _, pr := range prs {
            r.scanText(repoName, "pull_request", pr.GetTitle(), pr.GetHTMLURL())
            r.scanText(repoName, "pull_request", pr.GetBody(), pr.GetHTMLURL())
        }
        if resp.NextPage == 0 {
            break
        }
        opts.Page = resp.NextPage
    }
}

func (r *Reaper) scanIssues(repoName string) {
    opts := &github.IssueListByRepoOptions{State: "all", ListOptions: github.ListOptions{PerPage: 50}}
    for {
        select {
        case <-r.ctx.Done():
            return
        default:
        }
        if err := r.limiter.Wait(r.ctx); err != nil {
            return
        }
        issues, resp, err := r.client.Issues.ListByRepo(r.ctx, getOwner(repoName), getRepoName(repoName), opts)
        if err != nil {
            return
        }
        for _, issue := range issues {
            r.scanText(repoName, "issue", issue.GetTitle(), issue.GetHTMLURL())
            r.scanText(repoName, "issue", issue.GetBody(), issue.GetHTMLURL())
        }
        if resp.NextPage == 0 {
            break
        }
        opts.Page = resp.NextPage
    }
}

func (r *Reaper) scanCommitHistory(repoName, branch string) {
    opts := &github.CommitsListOptions{
        SHA: branch,
        ListOptions: github.ListOptions{PerPage: 100},
    }
    for {
        select {
        case <-r.ctx.Done():
            return
        default:
        }
        if err := r.limiter.Wait(r.ctx); err != nil {
            return
        }
        commits, resp, err := r.client.Repositories.ListCommits(r.ctx, getOwner(repoName), getRepoName(repoName), opts)
        if err != nil {
            return
        }
        for _, commit := range commits {
            if commit.Commit != nil {
                r.scanText(repoName, "commit_message", commit.Commit.GetMessage(), commit.GetHTMLURL())
            }
        }
        if resp.NextPage == 0 {
            break
        }
        opts.Page = resp.NextPage
    }
}

func (r *Reaper) scanText(repoName, location, text, url string) {
    if text == "" {
        return
    }
    for _, pattern := range r.patterns {
        matches := pattern.Regex.FindAllStringSubmatch(text, -1)
        for _, match := range matches {
            secret := match[0]
            if len(match) > 1 && match[1] != "" {
                secret = match[1]
            }
            if *entropyCheck && pattern.Entropy && !hasHighEntropy(secret) {
                continue
            }
            
            // Special handling for Email Addresses
            if pattern.Name == "Email Address" {
                if *hideObfuscated && isObfuscatedEmail(secret) {
                    continue
                }
                if isGitHubNoReply(secret) {
                    continue
                }
                if r.isDuplicateEmail(repoName, secret) {
                    continue
                }
            }
            
            hash := sha256.Sum256([]byte(repoName + location + secret))
            id := hex.EncodeToString(hash[:])[:16]
            finding := &Finding{
                ID:          id,
                Repository:  repoName,
                FilePath:    location,
                SecretType:  pattern.Name,
                SecretValue: maskSecret(secret),
                Context:     text,
                URL:         url,
                Timestamp:   time.Now(),
                Severity:    pattern.Severity,
            }
            r.results <- finding
        }
    }
}

func (r *Reaper) fetchAdvisories(repoName, owner, repo string) {
    query := fmt.Sprintf(`{
  repository(owner: "%s", name: "%s") {
    vulnerabilityAlerts(first: 100) {
      nodes {
        securityAdvisory {
          ghsaId
          cveId
          summary
          severity
          publishedAt
          updatedAt
          permalink
        }
        vulnerableManifestPath
      }
    }
  }
}`, owner, repo)
    
    body := struct {
        Query string `json:"query"`
    }{Query: query}
    jsonBody, _ := json.Marshal(body)
    
    req, err := http.NewRequestWithContext(r.ctx, "POST", "https://api.github.com/graphql", bytes.NewReader(jsonBody))
    if err != nil {
        return
    }
    req.Header.Set("Authorization", "Bearer "+os.Getenv("GITHUB_TOKEN"))
    req.Header.Set("Content-Type", "application/json")
    
    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return
    }
    defer resp.Body.Close()
    
    var result struct {
        Data struct {
            Repository struct {
                VulnerabilityAlerts struct {
                    Nodes []struct {
                        SecurityAdvisory struct {
                            GhsaId      string    `json:"ghsaId"`
                            CveId       string    `json:"cveId"`
                            Summary     string    `json:"summary"`
                            Severity    string    `json:"severity"`
                            PublishedAt time.Time `json:"publishedAt"`
                            UpdatedAt   time.Time `json:"updatedAt"`
                            Permalink   string    `json:"permalink"`
                        } `json:"securityAdvisory"`
                        VulnerableManifestPath string `json:"vulnerableManifestPath"`
                    } `json:"nodes"`
                } `json:"vulnerabilityAlerts"`
            } `json:"repository"`
        } `json:"data"`
    }
    
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return
    }
    
    for _, node := range result.Data.Repository.VulnerabilityAlerts.Nodes {
        adv := &Advisory{
            Repository:         repoName,
            GHSAID:             node.SecurityAdvisory.GhsaId,
            CVEID:              node.SecurityAdvisory.CveId,
            Summary:            node.SecurityAdvisory.Summary,
            Severity:           node.SecurityAdvisory.Severity,
            PublishedAt:        node.SecurityAdvisory.PublishedAt,
            UpdatedAt:          node.SecurityAdvisory.UpdatedAt,
            Permalink:          node.SecurityAdvisory.Permalink,
            VulnerableManifest: node.VulnerableManifestPath,
        }
        r.advisories <- adv
    }
}

func (r *Reaper) processResults() {
    for finding := range r.results {
        r.stats.mu.Lock()
        r.stats.FindingsFound++
        currentFindings := r.stats.FindingsFound
        r.stats.mu.Unlock()
        
        record := []string{
            finding.Timestamp.Format(time.RFC3339),
            finding.Repository,
            finding.FilePath,
            fmt.Sprintf("%d", finding.LineNumber),
            finding.SecretType,
            finding.SecretValue,
            finding.URL,
            finding.Severity,
        }
        r.csvWriter.Write(record)
        r.csvWriter.Flush()
        
        jsonData, _ := json.Marshal(finding)
        r.jsonFile.Write(append(jsonData, '\n'))
        r.jsonFile.Sync()
        
        if *verbose {
            fmt.Printf("\n[SECRET] #%d: %s [%s] in %s - %s\n", currentFindings, finding.SecretType, finding.Severity, finding.Repository, finding.FilePath)
        } else {
            fmt.Printf(".")
        }
    }
}

func (r *Reaper) processAdvisories() {
    for advisory := range r.advisories {
        r.stats.mu.Lock()
        r.stats.AdvisoriesFound++
        r.stats.mu.Unlock()
        
        jsonData, _ := json.Marshal(advisory)
        r.advFile.Write(append(jsonData, '\n'))
        r.advFile.Sync()
        
        if *verbose {
            fmt.Printf("\n[ADVISORY] %s [%s] in %s - %s\n", advisory.GHSAID, advisory.Severity, advisory.Repository, advisory.Summary)
        }
    }
}

func (r *Reaper) buildSearchQuery() string {
    query := "a is:public"
    if *sinceDays > 0 {
        since := time.Now().AddDate(0, 0, -*sinceDays).Format("2006-01-02")
        query += fmt.Sprintf(" pushed:>%s", since)
    }
    return query
}

func (r *Reaper) saveScannedList() {
    r.mu.Lock()
    defer r.mu.Unlock()
    file, err := os.Create(filepath.Join(*outputDir, "scanned_repos.txt"))
    if err != nil {
        return
    }
    defer file.Close()
    for repo := range r.scannedRepos {
        file.WriteString(repo + "\n")
    }
}

func (r *Reaper) printFinalStats() {
    duration := time.Since(r.stats.StartTime)
    fmt.Println("\n" + strings.Repeat("=", 60))
    fmt.Println("REAPER FINAL STATISTICS")
    fmt.Println(strings.Repeat("=", 60))
    fmt.Printf("Total runtime:       %s\n", duration.Round(time.Second))
    fmt.Printf("Repositories:        %d\n", r.stats.ReposScanned)
    fmt.Printf("Files scanned:       %d\n", r.stats.FilesScanned)
    fmt.Printf("Secrets found:       %d\n", r.stats.FindingsFound)
    fmt.Printf("Advisories found:    %d\n", r.stats.AdvisoriesFound)
    fmt.Printf("Rate limit hits:     %d\n", r.stats.RateLimitHits)
    fmt.Printf("Output directory:    %s\n", *outputDir)
    fmt.Println(strings.Repeat("=", 60))
    fmt.Println("\nDISCLAIMER: This tool is for educational and authorized testing only.")
    fmt.Println("Use responsibly and in compliance with GitHub's Terms of Service.")
}

func getOwner(repoName string) string {
    parts := strings.Split(repoName, "/")
    if len(parts) > 0 {
        return parts[0]
    }
    return ""
}

func getRepoName(repoName string) string {
    parts := strings.Split(repoName, "/")
    if len(parts) > 1 {
        return parts[1]
    }
    return repoName
}

func maskSecret(secret string) string {
    if len(secret) <= 12 {
        return "***MASKED***"
    }
    return secret[:6] + "..." + secret[len(secret)-6:]
}

func getContext(lines []string, lineNum, contextLines int) string {
    start := lineNum - contextLines
    if start < 0 {
        start = 0
    }
    end := lineNum + contextLines + 1
    if end > len(lines) {
        end = len(lines)
    }
    return strings.Join(lines[start:end], "\n")
}

func hasHighEntropy(s string) bool {
    if len(s) < 8 {
        return false
    }
    freq := make(map[rune]float64)
    for _, char := range s {
        freq[char]++
    }
    var entropy float64
    for _, f := range freq {
        p := f / float64(len(s))
        entropy -= p * math.Log2(p)
    }
    return entropy > 4.5
}
