<style type="text/css">
    * {box-sizing: border-box}

    /* Set height of body and the document to 100% */
    body, html {
        height: 100%;
        margin: 0;
        font-family: Arial;
        padding: 20px;
    }
    .accordion-toggle[aria-expanded="true"] i.fas.fa-angle-down {
        display: none;
    }
    .accordion-toggle[aria-expanded="false"] i.fas.fa-angle-up {
        display: none;
    }
    .pf-c-table thead,
    .pf-c-table .pf-m-truncate {
        --pf-c-table--cell--MaxWidth: none !important;
    }

    .pf-c-table thead, .pf-c-table .pf-m-truncate {
        --pf-c-table--cell--MinWidth: none !important;
    }
    .hiddenRow {
        padding: 0 !important;
    }
    .accordion {
        background-color: #eee;
        /*color: #444;*/
        color:#06c;

        cursor: pointer;
        padding: 18px;
        width: 100%;
        border: none;
        text-align: left;
        outline: none;
        font-size: 15px;
        transition: 0.4s;
    }

    .active, .accordion:hover {
        background-color: #ccc;
    }

    .accordion:after {
        content: '\002B';
        color: #777;
        font-weight: bold;
        float: right;
        margin-left: 5px;
    }

    .active:after {
        content: "\2212";
    }

    .panel {
        padding: 0 18px;
        background-color: white;
        max-height: 0;
        overflow: hidden;
        transition: max-height 0.2s ease-out;
    }
    .panel2 {
        padding: 0 18px;
        display: none;
        background-color: white;
        overflow: hidden;
    }

    /* Style tab links */
    .tablink {
        background-color: #555;
        color: white;
        float: left;
        border: none;
        outline: none;
        cursor: pointer;
        padding: 14px 16px;
        font-size: 17px;
        width: 25%;
    }

    .tablink:hover {
        background-color: #777;
    }

    /* Style the tab content (and add height:100% for full page content) */
    .tabcontent {
        color: black;
        display: none;
        padding: 100px 20px;
        height: fit-content;
    }

    /*#redhat {background-color: red;}*/
</style>