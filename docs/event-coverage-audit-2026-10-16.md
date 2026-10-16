# Event coverage audit

This is a type-level reconciliation of raw `events.json` and the inline `report.json` view.
The current schema has no stable event id, so equal EventType values are not treated as the same individual event.
A report omission is therefore a report-view omission; it does not prove that the collector missed the event.

| source | job | sample | raw | report | omitted | dynamic raw | dynamic report | dynamic omitted |
|---|---|---|---:|---:|---:|---:|---:|---:|
| controlled | `b4745a32` | lab-combined-behavior.exe | 733 | 109 | 624 | 674 | 41 | 633 |
| controlled | `c5548427` | lab-file-drop.exe | 751 | 75 | 676 | 692 | 35 | 657 |
| controlled | `acb5d6d0` | lab-file-rename-delete.exe | 753 | 75 | 678 | 694 | 34 | 660 |
| controlled | `72440896` | lab-mutex-signal.exe | 742 | 71 | 671 | 683 | 33 | 650 |
| controlled | `1feb22d0` | lab-network-probe.exe | 730 | 79 | 651 | 671 | 35 | 636 |
| controlled | `d11d3637` | lab-process-discovery.exe | 814 | 74 | 740 | 750 | 32 | 718 |
| controlled | `0f52c540` | KSword.Sandbox.SmokeTests.exe | 713 | 113 | 600 | 654 | 53 | 601 |
| controlled | `c1ce8d1c` | lab-registry-run.exe | 722 | 85 | 637 | 663 | 39 | 624 |
| controlled | `663512a5` | lab-scheduled-task.exe | 717 | 79 | 638 | 658 | 33 | 625 |
| controlled | `5d4cdb51` | lab-script-launch.exe | 717 | 77 | 640 | 658 | 33 | 625 |
| real | `b54fd8e2` | agent-tesla-0abb.exe | 735 | 54 | 681 | 678 | 29 | 649 |
| real | `7015c402` | agent-tesla-cdae.exe | 736 | 53 | 683 | 679 | 29 | 650 |
| real | `85f52b63` | agent-tesla-e10a.exe | 705 | 53 | 652 | 648 | 29 | 619 |
| real | `22df5e12` | azorult-9d66.exe | 688 | 109 | 579 | 631 | 31 | 600 |
| real | `2c800d2d` | kpot-36dc.exe | 717 | 61 | 656 | 660 | 31 | 629 |
| real | `6e15f600` | kpot-67f8.exe | 699 | 59 | 640 | 642 | 36 | 606 |
| real | `41d06d63` | psixbot-ca30.exe | 714 | 97 | 617 | 657 | 31 | 626 |
| real | `3fa55f9f` | psixbot-ce0e.exe | 718 | 97 | 621 | 661 | 31 | 630 |
| real | `8809ae3f` | psixbot-d2ee.exe | 683 | 147 | 536 | 626 | 29 | 597 |
| real | `72310bdc` | trickbot-374e.exe | 780 | 69 | 711 | 661 | 35 | 626 |
