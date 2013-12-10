ngx_filestats_module
====================

Nginx module for get statistics about times recieved static content.

Config example:
location /filestats {
                filestats memsize=1m;
                filestats_refresh_interval 6000;
                filestats_html_table_width 95;
                filestats_html_table_height 95;
                filestats_file_size 5k 50k 500k;
                filestats_time_interval 10 20 40 80 200 10000; # in miliseconds
}

memsize - size of shared memory segment
filestats_refresh_interval - timeout, then page must reload.
filestats_html_table_width - width of web page
filestats_html_table_height - height of web page
filestats_file_size - size intervals for get statistics. As example filestat: 0<1row<=5k, 5k<2row<=50k, 50k<3row<=500k, 500k<4row<...
filestats_time_interval - like file size, but for column.
