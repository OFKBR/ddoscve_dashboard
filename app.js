/* =========================================================
   DDoSCVE Dashboard
   Stage 12.1 + 12.2 dashboard enhancement

   Data source:
       ./data/dashboard_data.json

   Responsibilities:
   - Load and validate the exported dashboard dataset
   - Populate filters
   - Apply shared filter state
   - Render summary cards, charts, and CVE table
   - Build reusable yearly category trend analytics
   - Render safe per-CVE detail views
   ========================================================= */

"use strict";


/* =========================================================
   CONSTANTS
   ========================================================= */

const DATA_URL = "./data/dashboard_data.json";
const SUPPORTED_SCHEMA_VERSION = "1.0";

const TREND_TOP_N = 6;
const TREND_OTHER_LABEL = "Other";
const PARTIAL_YEAR = 2026;

const TREND_COLOR_PALETTE = [
    "#00d7c3",
    "#00a8e8",
    "#e52b85",
    "#20c76f",
    "#f4a340",
    "#8f7df0",
    "#f3d75b",
    "#ef3f55",
    "#6bc5d2",
];

const DEFAULT_FILTERS = {
    search: "",
    relevance: "relevant",
    year: "all",
    protocol: "all",
    cwe: "all",
    mechanism: "all",
    kev: "all",
    cvssMin: "",
    confidenceMin: "",
};


/* =========================================================
   APPLICATION STATE
   ========================================================= */

const state = {
    data: null,
    records: [],
    filteredRecords: [],

    charts: {
        timeline: null,
        mechanism: null,
        protocol: null,
        mechanismTrend: null,
        cweTrend: null,
        protocolTrend: null,
        simpleCrashTrend: null,
    },
};


/* =========================================================
   DOM REFERENCES
   ========================================================= */

const dom = {
    datasetStatus: document.getElementById("dataset-status-text"),

    searchInput: document.getElementById("search-input"),
    relevanceFilter: document.getElementById("relevance-filter"),
    yearFilter: document.getElementById("year-filter"),
    protocolFilter: document.getElementById("protocol-filter"),
    cweFilter: document.getElementById("cwe-filter"),
    mechanismFilter: document.getElementById("mechanism-filter"),
    kevFilter: document.getElementById("kev-filter"),
    cvssMin: document.getElementById("cvss-min"),
    confidenceMin: document.getElementById("confidence-min"),
    resetFilters: document.getElementById("reset-filters"),

    summaryTotal: document.getElementById("summary-total"),
    summaryRelevant: document.getElementById("summary-relevant"),
    summaryProtocol: document.getElementById("summary-protocol"),
    summaryKev: document.getElementById("summary-kev"),

    timelineCanvas: document.getElementById("timeline-chart"),
    mechanismCanvas: document.getElementById("mechanism-chart"),
    protocolCanvas: document.getElementById("protocol-chart"),

    mechanismTrendCanvas: document.getElementById("mechanism-trend-chart"),
    cweTrendCanvas: document.getElementById("cwe-trend-chart"),
    protocolTrendCanvas: document.getElementById("protocol-trend-chart"),
    simpleCrashTrendCanvas: document.getElementById("simple-crash-trend-chart"),

    recordsCount: document.getElementById("records-count"),
    tableBody: document.getElementById("cve-table-body"),

    detailsDialog: document.getElementById("cve-details-dialog"),
    detailsClose: document.getElementById("details-close"),
    detailsCveId: document.getElementById("details-cve-id"),
    detailsSummary: document.getElementById("details-summary"),
    detailsMetadata: document.getElementById("details-metadata"),
    detailsProtocol: document.getElementById("details-protocol"),
    detailsDlv: document.getElementById("details-dlv"),
    detailsReferences: document.getElementById("details-references"),
};


/* =========================================================
   INITIALIZATION
   ========================================================= */

document.addEventListener("DOMContentLoaded", initializeDashboard);

async function initializeDashboard() {
    try {
        setDatasetStatus("Loading dataset...");

        const data = await loadDashboardData();
        validateDataset(data);

        state.data = data;
        state.records = data.records;

        populateFilterOptions();
        bindEvents();
        applyFilters();

        const totalRecords = state.records.length;
        const scope = data.aggregation_scope || "unknown";

        setDatasetStatus(
            `${formatInteger(totalRecords)} records · schema ${data.schema_version} · aggregate scope: ${scope}`
        );
    } catch (error) {
        console.error("DDoSCVE dashboard initialization failed:", error);

        setDatasetStatus("Dataset load failed");
        showFatalError(
            "Unable to load dashboard data. Run the dashboard through a local HTTP server and verify that data/dashboard_data.json exists."
        );
    }
}


/* =========================================================
   DATA LOADING / VALIDATION
   ========================================================= */

async function loadDashboardData() {
    const response = await fetch(DATA_URL, {
        cache: "no-store",
    });

    if (!response.ok) {
        throw new Error(
            `Failed to load ${DATA_URL}: HTTP ${response.status}`
        );
    }

    return response.json();
}


function validateDataset(data) {
    if (!data || typeof data !== "object") {
        throw new Error("Dashboard dataset is not a JSON object.");
    }

    if (data.schema_version !== SUPPORTED_SCHEMA_VERSION) {
        throw new Error(
            `Unsupported dashboard schema version: ${data.schema_version ?? "missing"}`
        );
    }

    if (!Array.isArray(data.records)) {
        throw new Error("Dashboard dataset is missing records[].");
    }

    if (!data.summary || typeof data.summary !== "object") {
        throw new Error("Dashboard dataset is missing summary.");
    }
}


/* =========================================================
   FILTER SETUP
   ========================================================= */

function populateFilterOptions() {
    const years = uniqueSorted(
        state.records
            .map((record) => record.year)
            .filter((value) => Number.isFinite(value)),
        (a, b) => b - a
    );

    const protocols = uniqueSorted(
        state.records.flatMap(
            (record) => record.protocol_context?.protocols ?? []
        )
    );

    const cwes = uniqueSorted(
        state.records.flatMap((record) => record.cwe ?? [])
    );

    const mechanisms = uniqueSorted(
        state.records
            .filter(isRelevantRecord)
            .map((record) => record.dlv?.mechanism)
            .filter(Boolean)
    );

    populateSelect(
        dom.yearFilter,
        years,
        "All years",
        (value) => String(value)
    );

    populateSelect(
        dom.protocolFilter,
        protocols,
        "All protocols"
    );

    populateSelect(
        dom.cweFilter,
        cwes,
        "All CWEs"
    );

    populateSelect(
        dom.mechanismFilter,
        mechanisms,
        "All mechanisms",
        prettifyLabel
    );
}


function populateSelect(
    selectElement,
    values,
    allLabel,
    labelFormatter = (value) => value
) {
    clearElement(selectElement);

    const allOption = document.createElement("option");
    allOption.value = "all";
    allOption.textContent = allLabel;
    selectElement.appendChild(allOption);

    for (const value of values) {
        const option = document.createElement("option");
        option.value = String(value);
        option.textContent = labelFormatter(value);
        selectElement.appendChild(option);
    }
}


/* =========================================================
   FILTER EVENTS
   ========================================================= */

function bindEvents() {
    const immediateFilters = [
        dom.relevanceFilter,
        dom.yearFilter,
        dom.protocolFilter,
        dom.cweFilter,
        dom.mechanismFilter,
        dom.kevFilter,
    ];

    for (const element of immediateFilters) {
        element.addEventListener("change", applyFilters);
    }

    dom.searchInput.addEventListener("input", applyFilters);
    dom.cvssMin.addEventListener("input", applyFilters);
    dom.confidenceMin.addEventListener("input", applyFilters);

    dom.resetFilters.addEventListener("click", resetFilters);

    dom.detailsClose.addEventListener("click", () => {
        dom.detailsDialog.close();
    });

    dom.detailsDialog.addEventListener("click", (event) => {
        if (event.target === dom.detailsDialog) {
            dom.detailsDialog.close();
        }
    });
}


/* =========================================================
   FILTERING
   ========================================================= */

function applyFilters() {
    const filters = readFilters();

    state.filteredRecords = state.records
        .filter((record) => recordMatchesFilters(record, filters))
        .sort(compareRecords);

    renderDashboard();
}


function readFilters() {
    return {
        search: dom.searchInput.value.trim().toLowerCase(),
        relevance: dom.relevanceFilter.value,
        year: dom.yearFilter.value,
        protocol: dom.protocolFilter.value,
        cwe: dom.cweFilter.value,
        mechanism: dom.mechanismFilter.value,
        kev: dom.kevFilter.value,
        cvssMin: parseOptionalNumber(dom.cvssMin.value),
        confidenceMin: parseOptionalNumber(dom.confidenceMin.value),
    };
}


function recordMatchesFilters(record, filters) {
    if (filters.search && !recordMatchesSearch(record, filters.search)) {
        return false;
    }

    if (filters.relevance === "relevant_without_simple_crash") {
        if (!isRelevantRecord(record) || record.flags?.simple_crash === true) {
            return false;
        }
    } else if (
        filters.relevance !== "all" &&
        record.dlv?.relevance !== filters.relevance
    ) {
        return false;
    }

    if (
        filters.year !== "all" &&
        String(record.year) !== filters.year
    ) {
        return false;
    }

    if (
        filters.protocol !== "all" &&
        !(record.protocol_context?.protocols ?? []).includes(filters.protocol)
    ) {
        return false;
    }

    if (
        filters.cwe !== "all" &&
        !(record.cwe ?? []).includes(filters.cwe)
    ) {
        return false;
    }

    if (
        filters.mechanism !== "all" &&
        (
            !isRelevantRecord(record) ||
            record.dlv?.mechanism !== filters.mechanism
        )
    ) {
        return false;
    }

    if (
        filters.kev !== "all" &&
        Boolean(record.kev) !== (filters.kev === "true")
    ) {
        return false;
    }

    if (filters.cvssMin !== null) {
        const score = record.cvss?.score;

        if (!Number.isFinite(score) || score < filters.cvssMin) {
            return false;
        }
    }

    if (filters.confidenceMin !== null) {
        const confidence = record.dlv?.confidence;

        if (
            !Number.isFinite(confidence) ||
            confidence < filters.confidenceMin
        ) {
            return false;
        }
    }

    return true;
}


function recordMatchesSearch(record, query) {
    const searchableText = [
        record.cve_id,
        record.description,
        ...(record.vendors ?? []),
        ...(record.products ?? []),
    ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();

    return searchableText.includes(query);
}


function resetFilters() {
    dom.searchInput.value = DEFAULT_FILTERS.search;
    dom.relevanceFilter.value = DEFAULT_FILTERS.relevance;
    dom.yearFilter.value = DEFAULT_FILTERS.year;
    dom.protocolFilter.value = DEFAULT_FILTERS.protocol;
    dom.cweFilter.value = DEFAULT_FILTERS.cwe;
    dom.mechanismFilter.value = DEFAULT_FILTERS.mechanism;
    dom.kevFilter.value = DEFAULT_FILTERS.kev;
    dom.cvssMin.value = DEFAULT_FILTERS.cvssMin;
    dom.confidenceMin.value = DEFAULT_FILTERS.confidenceMin;

    applyFilters();
}


/* =========================================================
   DASHBOARD RENDERING
   ========================================================= */

function renderDashboard() {
    renderSummaryCards();
    renderTimelineChart();
    renderMechanismChart();
    renderProtocolChart();
    renderMechanismTrendChart();
    renderCweTrendChart();
    renderProtocolTrendChart();
    renderSimpleCrashTrendChart();
    renderTable();
}


/* =========================================================
   SUMMARY CARDS
   ========================================================= */

function renderSummaryCards() {
    const records = state.filteredRecords;

    const relevantCount = records.filter(
        (record) => record.dlv?.relevance === "relevant"
    ).length;

    const protocolCount = records.filter(
        (record) => record.protocol_context?.available === true
    ).length;

    const kevCount = records.filter(
        (record) => record.kev === true
    ).length;

    dom.summaryTotal.textContent = formatInteger(records.length);
    dom.summaryRelevant.textContent = formatInteger(relevantCount);
    dom.summaryProtocol.textContent = formatInteger(protocolCount);
    dom.summaryKev.textContent = formatInteger(kevCount);
}


/* =========================================================
   CHARTS
   ========================================================= */

function renderTimelineChart() {
    const counts = countBy(
        state.filteredRecords,
        (record) => record.year,
        (value) => Number.isFinite(value)
    );

    const entries = [...counts.entries()]
        .sort((a, b) => Number(a[0]) - Number(b[0]));

    state.charts.timeline = replaceChart(
        state.charts.timeline,
        dom.timelineCanvas,
        {
            type: "line",
            data: {
                labels: entries.map(([year]) => formatYearLabel(Number(year))),
                datasets: [
                    {
                        label: "CVEs",
                        data: entries.map(([, count]) => count),
                        borderColor: cssVar("--accent"),
                        backgroundColor: transparentize(
                            cssVar("--accent"),
                            0.80
                        ),
                        pointBackgroundColor: cssVar("--accent"),
                        pointBorderColor: cssVar("--accent"),
                        pointRadius: 3,
                        pointHoverRadius: 4,
                        borderWidth: 2,
                        tension: 0.2,
                        fill: true,
                    },
                ],
            },
            options: chartOptions({
                showLegend: false,
            }),
        }
    );
}


function renderMechanismChart() {
    const relevantRecords = state.filteredRecords.filter(isRelevantRecord);

    const counts = countBy(
        relevantRecords,
        (record) => record.dlv?.mechanism,
        Boolean
    );

    const entries = sortCountsDescending(counts);

    state.charts.mechanism = replaceChart(
        state.charts.mechanism,
        dom.mechanismCanvas,
        {
            type: "bar",
            data: {
                labels: entries.map(([mechanism]) =>
                    prettifyLabel(mechanism)
                ),
                datasets: [
                    {
                        label: "CVEs",
                        data: entries.map(([, count]) => count),
                        backgroundColor: transparentize(
                            cssVar("--accent-pink"),
                            0.18
                        ),
                        borderColor: cssVar("--accent-pink"),
                        borderWidth: 1,
                    },
                ],
            },
            options: chartOptions({
                indexAxis: "y",
                showLegend: false,
            }),
        }
    );
}


function renderProtocolChart() {
    const counts = new Map();

    for (const record of state.filteredRecords) {
        const protocols = new Set(
            record.protocol_context?.protocols ?? []
        );

        for (const protocol of protocols) {
            counts.set(
                protocol,
                (counts.get(protocol) ?? 0) + 1
            );
        }
    }

    const entries = sortCountsDescending(counts);

    state.charts.protocol = replaceChart(
        state.charts.protocol,
        dom.protocolCanvas,
        {
            type: "bar",
            data: {
                labels: entries.map(([protocol]) => protocol),
                datasets: [
                    {
                        label: "CVEs",
                        data: entries.map(([, count]) => count),
                        backgroundColor: transparentize(
                            cssVar("--accent-blue"),
                            0.18
                        ),
                        borderColor: cssVar("--accent-blue"),
                        borderWidth: 1,
                    },
                ],
            },
            options: chartOptions({
                indexAxis: "y",
                showLegend: false,
            }),
        }
    );
}


/* =========================================================
   STAGE 12.1 TREND ANALYTICS

   Count semantics:
   - Mechanism analytics include only CVEs with relevance == "relevant".
   - Mechanism is single-label: one relevant CVE contributes once.
   - CWE and Protocol are multi-label: one CVE contributes once
     to every distinct label attached to that CVE.
   - CWE/Protocol charts keep the top N labels and aggregate all
     remaining label occurrences into "Other".
   ========================================================= */

function renderMechanismTrendChart() {
    if (!dom.mechanismTrendCanvas) {
        return;
    }

    const relevantRecords = state.filteredRecords.filter(isRelevantRecord);

    const trend = buildYearlyCategoryTrend(
        relevantRecords,
        (record) => record.dlv?.mechanism
            ? [record.dlv.mechanism]
            : []
    );

    state.charts.mechanismTrend = renderStackedTrendChart(
        state.charts.mechanismTrend,
        dom.mechanismTrendCanvas,
        trend,
        {
            labelFormatter: prettifyLabel,
        }
    );
}


function renderCweTrendChart() {
    if (!dom.cweTrendCanvas) {
        return;
    }

    const trend = buildYearlyCategoryTrend(
        state.filteredRecords,
        (record) => record.cwe ?? [],
        {
            topN: TREND_TOP_N,
        }
    );

    state.charts.cweTrend = renderStackedTrendChart(
        state.charts.cweTrend,
        dom.cweTrendCanvas,
        trend
    );
}


function renderProtocolTrendChart() {
    if (!dom.protocolTrendCanvas) {
        return;
    }

    const trend = buildYearlyCategoryTrend(
        state.filteredRecords,
        (record) => record.protocol_context?.protocols ?? [],
        {
            topN: TREND_TOP_N,
        }
    );

    state.charts.protocolTrend = renderStackedTrendChart(
        state.charts.protocolTrend,
        dom.protocolTrendCanvas,
        trend
    );
}

function renderSimpleCrashTrendChart() {
    if (!dom.simpleCrashTrendCanvas) {
        return;
    }

    const relevantRecords = state.filteredRecords.filter(isRelevantRecord);
    const trend = buildSimpleCrashTrend(relevantRecords);

    state.charts.simpleCrashTrend = renderStackedTrendChart(
        state.charts.simpleCrashTrend,
        dom.simpleCrashTrendCanvas,
        trend
    );
}


function buildSimpleCrashTrend(records) {
    const countsByYear = new Map();

    for (const record of records) {
        const year = record.year;

        if (!Number.isFinite(year)) {
            continue;
        }

        if (!countsByYear.has(year)) {
            countsByYear.set(year, {
                simpleCrash: 0,
                otherRelevant: 0,
            });
        }

        const counts = countsByYear.get(year);

        if (record.flags?.simple_crash === true) {
            counts.simpleCrash += 1;
        } else {
            counts.otherRelevant += 1;
        }
    }

    const years = [...countsByYear.keys()].sort((a, b) => a - b);

    return {
        years,
        series: [
            {
                category: "Simple crash",
                data: years.map((year) =>
                    countsByYear.get(year)?.simpleCrash ?? 0
                ),
            },
            {
                category: "Other relevant DoS/DDoS",
                data: years.map((year) =>
                    countsByYear.get(year)?.otherRelevant ?? 0
                ),
            },
        ],
    };
}



function buildYearlyCategoryTrend(
    records,
    categoryFunction,
    {
        topN = null,
        otherLabel = TREND_OTHER_LABEL,
    } = {}
) {
    const years = new Set();
    const countsByYear = new Map();
    const totalsByCategory = new Map();

    for (const record of records) {
        const year = record.year;

        if (!Number.isFinite(year)) {
            continue;
        }

        years.add(year);

        if (!countsByYear.has(year)) {
            countsByYear.set(year, new Map());
        }

        const yearCounts = countsByYear.get(year);
        const categories = distinctCategoryValues(
            categoryFunction(record)
        );

        for (const category of categories) {
            yearCounts.set(
                category,
                (yearCounts.get(category) ?? 0) + 1
            );

            totalsByCategory.set(
                category,
                (totalsByCategory.get(category) ?? 0) + 1
            );
        }
    }

    const sortedYears = [...years].sort((a, b) => a - b);
    const sortedCategories = sortCountsDescending(totalsByCategory)
        .map(([category]) => category);

    const shouldGroupOther =
        Number.isInteger(topN) &&
        topN > 0 &&
        sortedCategories.length > topN;

    const primaryCategories = shouldGroupOther
        ? sortedCategories.slice(0, topN)
        : sortedCategories;

    const primaryCategorySet = new Set(primaryCategories);

    const series = primaryCategories.map((category) => ({
        category,
        data: sortedYears.map((year) =>
            countsByYear.get(year)?.get(category) ?? 0
        ),
    }));

    if (shouldGroupOther) {
        series.push({
            category: otherLabel,
            data: sortedYears.map((year) => {
                const yearCounts = countsByYear.get(year) ?? new Map();
                let otherCount = 0;

                for (const [category, count] of yearCounts.entries()) {
                    if (!primaryCategorySet.has(category)) {
                        otherCount += count;
                    }
                }

                return otherCount;
            }),
        });
    }

    return {
        years: sortedYears,
        series,
    };
}


function distinctCategoryValues(values) {
    const rawValues = Array.isArray(values)
        ? values
        : values === null || values === undefined
            ? []
            : [values];

    return [...new Set(
        rawValues
            .map((value) => String(value).trim())
            .filter(Boolean)
    )];
}


function renderStackedTrendChart(
    existingChart,
    canvas,
    trend,
    {
        labelFormatter = (value) => value,
    } = {}
) {
    const datasets = trend.series.map((series, index) => {
        const color = trendSeriesColor(index);

        return {
            label: labelFormatter(series.category),
            data: series.data,
            backgroundColor: transparentize(color, 0.14),
            borderColor: color,
            borderWidth: 1,
        };
    });

    return replaceChart(
        existingChart,
        canvas,
        {
            type: "bar",
            data: {
                labels: trend.years.map((year) => formatYearLabel(year)),
                datasets,
            },
            options: chartOptions({
                showLegend: true,
                stacked: true,
                tooltipDisplayColors: true,
                interactionMode: "index",
                hideZeroTooltipItems: true,
            }),
        }
    );
}


function formatYearLabel(year) {
    return year === PARTIAL_YEAR
        ? `${year}*`
        : String(year);
}


function trendSeriesColor(index) {
    return TREND_COLOR_PALETTE[
        index % TREND_COLOR_PALETTE.length
    ];
}


function replaceChart(existingChart, canvas, config) {
    if (existingChart) {
        existingChart.destroy();
    }

    if (typeof Chart === "undefined") {
        console.warn("Chart.js is unavailable. Charts will not be rendered.");
        return null;
    }

    return new Chart(canvas, config);
}


function chartOptions({
    indexAxis = "x",
    showLegend = false,
    stacked = false,
    tooltipDisplayColors = false,
    interactionMode = "nearest",
    hideZeroTooltipItems = false,
} = {}) {
    return {
        responsive: true,
        maintainAspectRatio: false,
        indexAxis,
        animation: {
            duration: 180,
        },
        interaction: {
            mode: interactionMode,
            intersect: false,
        },
        plugins: {
            legend: {
                display: showLegend,
                labels: {
                    color: cssVar("--text-secondary"),
                    boxWidth: 10,
                    boxHeight: 10,
                },
            },
            tooltip: {
                backgroundColor: "#111315",
                titleColor: cssVar("--text-main"),
                bodyColor: cssVar("--text-secondary"),
                borderColor: cssVar("--border"),
                borderWidth: 1,
                displayColors: tooltipDisplayColors,
                filter: hideZeroTooltipItems
                    ? (context) => Number(context.raw) > 0
                    : undefined,
            },
        },
        scales: {
            x: {
                beginAtZero: true,
                stacked,
                ticks: {
                    color: cssVar("--text-muted"),
                    precision: 0,
                    maxRotation: 0,
                    autoSkip: true,
                },
                grid: {
                    color: cssVar("--border-soft"),
                },
                border: {
                    color: cssVar("--border"),
                },
            },
            y: {
                beginAtZero: true,
                stacked,
                ticks: {
                    color: cssVar("--text-muted"),
                    precision: 0,
                },
                grid: {
                    color: cssVar("--border-soft"),
                },
                border: {
                    color: cssVar("--border"),
                },
            },
        },
    };
}


/* =========================================================
   CVE TABLE
   ========================================================= */

function renderTable() {
    clearElement(dom.tableBody);

    const records = state.filteredRecords;

    dom.recordsCount.textContent =
        `Showing ${formatInteger(records.length)} of ${formatInteger(state.records.length)} records`;

    if (records.length === 0) {
        const row = document.createElement("tr");
        const cell = document.createElement("td");

        cell.colSpan = 9;
        cell.className = "empty-state";
        cell.textContent = "No CVE records match the current filters.";

        row.appendChild(cell);
        dom.tableBody.appendChild(row);

        return;
    }

    const fragment = document.createDocumentFragment();

    for (const record of records) {
        fragment.appendChild(createRecordRow(record));
    }

    dom.tableBody.appendChild(fragment);
}


function createRecordRow(record) {
    const row = document.createElement("tr");
    row.tabIndex = 0;

    row.addEventListener("click", () => openCveDetails(record));
    row.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            openCveDetails(record);
        }
    });

    row.appendChild(
        createTextCell(record.cve_id, "cve-link")
    );

    row.appendChild(
        createTextCell(
            Number.isFinite(record.year)
                ? String(record.year)
                : "—"
        )
    );

    row.appendChild(
        createTextCell(formatCvssShort(record.cvss))
    );

    row.appendChild(
        createTextCell(formatList(record.cwe))
    );

    row.appendChild(
        createBadgeListCell(
            record.protocol_context?.protocols ?? [],
            "badge-protocol"
        )
    );

    row.appendChild(
        createBadgeCell(
            prettifyLabel(record.dlv?.relevance ?? "unclassified"),
            relevanceBadgeClass(record.dlv?.relevance)
        )
    );

    row.appendChild(
        createBadgeCell(
            formatMechanismForDisplay(record),
            mechanismBadgeClassForRecord(record)
        )
    );

    row.appendChild(
        createTextCell(formatConfidence(record.dlv?.confidence))
    );

    row.appendChild(
        record.kev
            ? createBadgeCell("KEV", "badge-kev")
            : createTextCell("—")
    );

    return row;
}


function createTextCell(value, className = "") {
    const cell = document.createElement("td");

    if (className) {
        cell.className = className;
    }

    cell.textContent = value ?? "—";

    return cell;
}


function createBadgeCell(label, badgeClass = "") {
    const cell = document.createElement("td");
    const badge = createBadge(label, badgeClass);

    cell.appendChild(badge);

    return cell;
}


function createBadgeListCell(values, badgeClass = "") {
    const cell = document.createElement("td");

    if (!values || values.length === 0) {
        cell.textContent = "—";
        return cell;
    }

    values.forEach((value, index) => {
        if (index > 0) {
            cell.appendChild(document.createTextNode(" "));
        }

        cell.appendChild(createBadge(value, badgeClass));
    });

    return cell;
}


function createBadge(label, badgeClass = "") {
    const badge = document.createElement("span");

    badge.className = ["badge", badgeClass]
        .filter(Boolean)
        .join(" ");

    badge.textContent = label;

    return badge;
}


function relevanceBadgeClass(relevance) {
    switch (relevance) {
        case "relevant":
            return "badge-relevant";

        case "not relevant":
            return "badge-not-relevant";

        case "unclear":
            return "badge-unclear";

        default:
            return "";
    }
}


function mechanismBadgeClass(mechanism) {
    if (mechanism === "unclear") {
        return "badge-unclear";
    }

    return "badge-mechanism";
}


function isRelevantRecord(record) {
    return record.dlv?.relevance === "relevant";
}


function formatMechanismForDisplay(record) {
    if (record.dlv?.relevance === "not relevant") {
        return "N/A";
    }

    return prettifyLabel(record.dlv?.mechanism ?? "unclear");
}


function mechanismBadgeClassForRecord(record) {
    if (record.dlv?.relevance === "not relevant") {
        return "";
    }

    return mechanismBadgeClass(record.dlv?.mechanism);
}


/* =========================================================
   CVE DETAILS DIALOG
   ========================================================= */

function openCveDetails(record) {
    dom.detailsCveId.textContent = record.cve_id ?? "CVE";

    dom.detailsSummary.textContent = [
        record.year,
        record.cvss?.severity,
        record.dlv?.relevance
            ? prettifyLabel(record.dlv.relevance)
            : null,
    ]
        .filter(Boolean)
        .join(" · ");

    renderMetadataDetails(record);
    renderProtocolDetails(record);
    renderDlvDetails(record);
    renderReferenceDetails(record.references ?? []);

    dom.detailsDialog.showModal();
}


function renderMetadataDetails(record) {
    clearElement(dom.detailsMetadata);

    const grid = createDetailsGrid();

    appendDetailRow(grid, "Description", record.description || "—");
    appendDetailRow(grid, "Published", formatDate(record.published));
    appendDetailRow(grid, "Modified", formatDate(record.modified));
    appendDetailRow(
        grid,
        "Year",
        Number.isFinite(record.year)
            ? String(record.year)
            : "—"
    );
    appendDetailRow(grid, "CWE", formatList(record.cwe));
    appendDetailRow(grid, "Vendor", formatList(record.vendors));
    appendDetailRow(grid, "Product", formatList(record.products));
    appendDetailRow(
        grid,
        "CPE",
        formatCpe(record.cpe)
    );
    appendDetailRow(
        grid,
        "CVSS",
        formatCvssLong(record.cvss)
    );
    appendDetailRow(
        grid,
        "CVSS Vector",
        record.cvss?.vector || "—"
    );
    appendDetailRow(
        grid,
        "KEV",
        record.kev ? "Yes" : "No"
    );

    if (record.kev_metadata) {
        appendDetailRow(
            grid,
            "KEV Metadata",
            formatObject(record.kev_metadata)
        );
    }

    dom.detailsMetadata.appendChild(grid);
}


function renderProtocolDetails(record) {
    clearElement(dom.detailsProtocol);

    const context = record.protocol_context ?? {};
    const grid = createDetailsGrid();

    appendDetailRow(
        grid,
        "Available",
        context.available ? "Yes" : "No"
    );

    appendDetailRow(
        grid,
        "Protocols",
        formatList(context.protocols)
    );

    appendDetailRow(
        grid,
        "Primary Protocol",
        context.primary_protocol || "—"
    );

    appendDetailRow(
        grid,
        "Protocol Vector",
        context.protocol_vector || "—"
    );

    appendDetailRow(
        grid,
        "Relation",
        context.predicted_relation || "—"
    );

    appendDetailRow(
        grid,
        "Origin",
        context.predicted_origin || "—"
    );

    appendDetailRow(
        grid,
        "ProtoCVE Reasoning",
        context.reasoning || "—"
    );

    dom.detailsProtocol.appendChild(grid);
}


function renderDlvDetails(record) {
    clearElement(dom.detailsDlv);

    const dlv = record.dlv ?? {};
    const flags = record.flags ?? {};

    const grid = createDetailsGrid();

    appendDetailRow(
        grid,
        "Relevance",
        prettifyLabel(dlv.relevance ?? "—")
    );

    appendDetailRow(
        grid,
        "Mechanism",
        dlv.relevance === "not relevant"
            ? "N/A"
            : prettifyLabel(dlv.mechanism ?? "—")
    );

    appendDetailRow(
        grid,
        "Confidence",
        formatConfidence(dlv.confidence)
    );

    appendDetailRow(
        grid,
        "Explanation",
        dlv.explanation || "—"
    );

    appendDetailRow(
        grid,
        "Simple Crash",
        formatBoolean(flags.simple_crash)
    );

    appendDetailRow(
        grid,
        "Deprioritized",
        formatBoolean(flags.deprioritized)
    );

    appendDetailRow(
        grid,
        "Needs Manual Review",
        formatBoolean(flags.needs_manual_review)
    );

    appendDetailRow(
        grid,
        "LLM Error",
        formatBoolean(flags.llm_error)
    );

    appendDetailRow(
        grid,
        "LLM Missing Result",
        formatBoolean(flags.llm_missing_result)
    );

    dom.detailsDlv.appendChild(grid);
}


function renderReferenceDetails(references) {
    clearElement(dom.detailsReferences);

    if (!references.length) {
        dom.detailsReferences.textContent = "No references available.";
        return;
    }

    const list = document.createElement("div");
    list.className = "details-grid";

    references.forEach((reference, index) => {
        const label = document.createElement("div");
        label.className = "detail-label";
        label.textContent = `Reference ${index + 1}`;

        const value = document.createElement("div");
        value.className = "detail-value";

        const safeReference = safeUrl(reference);

        if (safeReference) {
            const link = document.createElement("a");

            link.href = safeReference;
            link.target = "_blank";
            link.rel = "noopener noreferrer";
            link.textContent = reference;

            value.appendChild(link);
        } else {
            value.textContent = reference;
        }

        list.appendChild(label);
        list.appendChild(value);
    });

    dom.detailsReferences.appendChild(list);
}


function createDetailsGrid() {
    const grid = document.createElement("div");
    grid.className = "details-grid";

    return grid;
}


function appendDetailRow(grid, labelText, valueText) {
    const label = document.createElement("div");
    label.className = "detail-label";
    label.textContent = labelText;

    const value = document.createElement("div");
    value.className = "detail-value";
    value.textContent = valueText ?? "—";

    grid.appendChild(label);
    grid.appendChild(value);
}


/* =========================================================
   HELPERS
   ========================================================= */

function clearElement(element) {
    while (element.firstChild) {
        element.removeChild(element.firstChild);
    }
}


function setDatasetStatus(message) {
    dom.datasetStatus.textContent = message;
}


function showFatalError(message) {
    const dashboard = document.querySelector(".dashboard");

    if (!dashboard) {
        return;
    }

    const error = document.createElement("div");
    error.className = "error-state";
    error.textContent = message;

    dashboard.prepend(error);
}


function uniqueSorted(values, comparator = defaultComparator) {
    return [...new Set(values)].sort(comparator);
}


function defaultComparator(a, b) {
    return String(a).localeCompare(
        String(b),
        undefined,
        {
            numeric: true,
            sensitivity: "base",
        }
    );
}


function compareRecords(a, b) {
    const yearA = Number.isFinite(a.year) ? a.year : -Infinity;
    const yearB = Number.isFinite(b.year) ? b.year : -Infinity;

    if (yearA !== yearB) {
        return yearB - yearA;
    }

    return String(a.cve_id ?? "").localeCompare(
        String(b.cve_id ?? ""),
        undefined,
        {
            numeric: true,
            sensitivity: "base",
        }
    );
}


function countBy(records, keyFunction, valuePredicate = () => true) {
    const counts = new Map();

    for (const record of records) {
        const value = keyFunction(record);

        if (!valuePredicate(value)) {
            continue;
        }

        counts.set(
            value,
            (counts.get(value) ?? 0) + 1
        );
    }

    return counts;
}


function sortCountsDescending(counts) {
    return [...counts.entries()].sort((a, b) => {
        if (a[1] !== b[1]) {
            return b[1] - a[1];
        }

        return defaultComparator(a[0], b[0]);
    });
}


function parseOptionalNumber(value) {
    if (value === "") {
        return null;
    }

    const number = Number(value);

    return Number.isFinite(number)
        ? number
        : null;
}


function formatInteger(value) {
    return Number(value).toLocaleString("en-US");
}


function formatList(values) {
    if (!values || values.length === 0) {
        return "—";
    }

    return values.join(", ");
}


function formatConfidence(value) {
    if (!Number.isFinite(value)) {
        return "—";
    }

    return `${Math.round(value * 100)}%`;
}


function formatCvssShort(cvss) {
    if (!cvss || !Number.isFinite(cvss.score)) {
        return "—";
    }

    return cvss.severity
        ? `${cvss.score.toFixed(1)} ${cvss.severity}`
        : cvss.score.toFixed(1);
}


function formatCvssLong(cvss) {
    if (!cvss || !Number.isFinite(cvss.score)) {
        return "—";
    }

    const parts = [
        cvss.score.toFixed(1),
        cvss.severity,
        cvss.version
            ? `CVSS ${cvss.version}`
            : null,
    ].filter(Boolean);

    return parts.join(" · ");
}


function formatDate(value) {
    if (!value) {
        return "—";
    }

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
        return value;
    }

    return date.toLocaleString("en-GB", {
        year: "numeric",
        month: "short",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
    });
}


function formatCpe(cpeEntries) {
    if (!cpeEntries || cpeEntries.length === 0) {
        return "—";
    }

    return cpeEntries
        .map((entry) => {
            if (typeof entry === "string") {
                return entry;
            }

            return entry.raw
                || [
                    entry.vendor,
                    entry.product,
                    entry.version,
                ]
                    .filter(Boolean)
                    .join(":");
        })
        .filter(Boolean)
        .join(", ");
}


function formatObject(value) {
    if (value === null || value === undefined) {
        return "—";
    }

    if (typeof value !== "object") {
        return String(value);
    }

    return Object.entries(value)
        .map(([key, item]) => {
            const formattedValue = Array.isArray(item)
                ? item.join(", ")
                : typeof item === "object" && item !== null
                    ? JSON.stringify(item)
                    : String(item ?? "—");

            return `${key}: ${formattedValue}`;
        })
        .join(" | ");
}


function formatBoolean(value) {
    if (value === true) {
        return "Yes";
    }

    if (value === false) {
        return "No";
    }

    return "—";
}


function prettifyLabel(value) {
    if (value === null || value === undefined) {
        return "—";
    }

    const text = String(value);

    if (!text) {
        return "—";
    }

    return text
        .split(/\s+/)
        .map((word) =>
            word.length
                ? word[0].toUpperCase() + word.slice(1)
                : word
        )
        .join(" ");
}


function safeUrl(value) {
    try {
        const url = new URL(value);

        if (!["http:", "https:"].includes(url.protocol)) {
            return null;
        }

        return url.href;
    } catch {
        return null;
    }
}


function cssVar(name) {
    return getComputedStyle(document.documentElement)
        .getPropertyValue(name)
        .trim();
}


function transparentize(color, amount) {
    if (!color.startsWith("#")) {
        return color;
    }

    const hex = color.slice(1);

    if (![3, 6].includes(hex.length)) {
        return color;
    }

    const normalized = hex.length === 3
        ? hex
            .split("")
            .map((char) => char + char)
            .join("")
        : hex;

    const red = parseInt(normalized.slice(0, 2), 16);
    const green = parseInt(normalized.slice(2, 4), 16);
    const blue = parseInt(normalized.slice(4, 6), 16);

    const alpha = Math.max(
        0,
        Math.min(1, 1 - amount)
    );

    return `rgba(${red}, ${green}, ${blue}, ${alpha})`;
}
