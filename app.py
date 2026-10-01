import sqlite3

import pandas as pd
import streamlit as st


st.set_page_config(
    page_title=(
        "OSINT Threat Intelligence Portal"
    ),
    page_icon="OT",
    layout="wide",
)


DB_PATH = "data/iocs.db"


@st.cache_data(ttl=60)
def load_data():

    conn = sqlite3.connect(
        DB_PATH
    )

    df = pd.read_sql_query(
        """
        SELECT
            ioc_type,
            value,
            risk_score,
            risk_level,
            sources_list AS sources,
            source_count,
            seen_count,

            first_seen
                AS collector_first_seen,

            last_seen
                AS collector_last_seen,

            source_first_seen,
            source_last_seen,
            source_status,
            feed_updated_at,
            source_url,
            source_details_json,

            score_source_confidence,
            score_freshness,
            score_corroboration,
            score_persistence,

            description

        FROM iocs
        """,
        conn,
    )

    conn.close()

    return df


st.title(
    "OSINT Threat Intelligence Portal"
)

st.caption(
    "Açıq feed-lərdən toplanmış, "
    "normallaşdırılmış və explainable "
    "risk score ilə zənginləşdirilmiş "
    "IOC bazası."
)


try:

    df = load_data()

    total = len(df)

    high_or_critical = len(
        df[
            df["risk_score"] >= 70
        ]
    )

    multi_source = len(
        df[
            df["source_count"] >= 2
        ]
    )

    observed = len(
        df[
            df[
                "collector_last_seen"
            ].notna()
        ]
    )

    c1, c2, c3, c4 = st.columns(4)

    c1.metric(
        "Ümumi IOC",
        f"{total:,}",
    )

    c2.metric(
        "High / Critical",
        f"{high_or_critical:,}",
    )

    c3.metric(
        "Multi-source",
        f"{multi_source:,}",
    )

    c4.metric(
        "Müşahidəsi olan",
        f"{observed:,}",
    )

    st.divider()

    st.sidebar.header(
        "Filter"
    )

    types = sorted(
        df[
            "ioc_type"
        ]
        .dropna()
        .unique()
        .tolist()
    )

    selected_types = (
        st.sidebar.multiselect(
            "IOC tipi",
            types,
            default=types,
        )
    )

    source_values = sorted(
        {
            source.strip()
            for value in (
                df["sources"]
                .dropna()
            )
            for source in (
                value.split(",")
            )
            if source.strip()
        }
    )

    selected_sources = (
        st.sidebar.multiselect(
            "Mənbə",
            source_values,
            default=source_values,
        )
    )

    min_score = (
        st.sidebar.slider(
            "Minimum risk score",
            min_value=0,
            max_value=100,
            value=0,
            step=5,
        )
    )

    search_query = (
        st.sidebar.text_input(
            "Axtarış",
            placeholder=(
                "IP, URL, domain və ya SHA256"
            ),
        )
    )

    filtered_df = df[
        (df["ioc_type"].isin(
            selected_types
        ))
        &
        (df["risk_score"] >= min_score)
    ]

    if selected_sources:

        filtered_df = (
            filtered_df[
                filtered_df[
                    "sources"
                ].apply(
                    lambda value:
                        any(
                            source
                            in (
                                value or ""
                            ).split(", ")
                            for source
                            in selected_sources
                        )
                )
            ]
        )

    if search_query:

        filtered_df = (
            filtered_df[
                filtered_df[
                    "value"
                ].str.contains(
                    search_query,
                    case=False,
                    na=False,
                )
                |
                filtered_df[
                    "description"
                ].str.contains(
                    search_query,
                    case=False,
                    na=False,
                )
            ]
        )

    st.subheader(
        f"Nəticələr — "
        f"{len(filtered_df):,} IOC"
    )

    export_df = (
        filtered_df.drop(
            columns=[
                "source_details_json"
            ],
            errors="ignore",
        )
    )

    col_csv, col_json = (
        st.columns(2)
    )

    with col_csv:

        st.download_button(
            "CSV endir",

            data=(
                export_df
                .to_csv(
                    index=False
                )
                .encode("utf-8")
            ),

            file_name=(
                "osint_iocs.csv"
            ),

            mime="text/csv",
        )

    with col_json:

        st.download_button(
            "JSON endir",

            data=(
                export_df
                .to_json(
                    orient="records",
                    indent=2,
                )
                .encode("utf-8")
            ),

            file_name=(
                "osint_iocs.json"
            ),

            mime="application/json",
        )

    display_columns = [
        "ioc_type",
        "value",
        "risk_score",
        "risk_level",
        "sources",
        "source_count",
        "seen_count",
        "source_first_seen",
        "collector_last_seen",
    ]

    st.dataframe(
        filtered_df[
            display_columns
        ].sort_values(
            [
                "risk_score",
                "collector_last_seen",
            ],
            ascending=[
                False,
                False,
            ],
        ),
        use_container_width=True,
        height=560,
        hide_index=True,
    )

    st.caption(
        "Score: Source confidence (40) + "
        "Freshness (30) + "
        "Corroboration (20) + "
        "Persistence (10). "
        "Source çəkiləri layihənin "
        "explainable modelinə aiddir."
    )


except Exception as exc:

    st.error(
        "Məlumatlar yüklənərkən "
        f"xəta baş verdi: {exc}"
    )
