
/**
 * Copyright (c) 2010-2012 Aleksey "0xc0dec" Fedotov
 * http://skbkontur.ru
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_filestats_module.h"

#define INTSIZE 254 
#define FILESTATS_STAT_START() (((u_char*)filestats_data->data))
#define FILESTATS_STAT_ADDRESS(size2time,time,maxtime) (((u_char*)filestats_data->data) + sizeof(ngx_uint_t) + (size2time*maxtime*sizeof(ngx_uint_t)) + ((time+1)*sizeof(ngx_uint_t)))

/**
 * Shared memory used to store statistics
 */
ngx_shm_zone_t * filestats_data = NULL;

static size_t filestats_data_size = 0;

typedef struct
{
    ngx_time_t times;
    ngx_uint_t len;
    ngx_uint_t count;
} ngx_http_filestats_timeouts_t;

typedef struct
{
    ssize_t size;
    ngx_uint_t strsize;
    ngx_list_t timeouts;
} ngx_http_filestats_time2size_t;

typedef struct
{
    /**
     * HTML table width and height.
     * Less or equal 100 - percent value, greater than 100 - pixel value.
     * 70 by default.
     */
    volatile ngx_uint_t is_reload;	
    ngx_uint_t html_table_width;
    ngx_uint_t html_table_height;
    /** Page refresh interval, milliseconds. 5000 by default */
    ngx_uint_t refresh_interval;
    ngx_list_t size2time;
} ngx_http_filestats_loc_conf_t;
ngx_http_filestats_loc_conf_t * filestats_conf = NULL;


static void * ngx_http_filestats_create_loc_conf(ngx_conf_t *cf);
static char * ngx_http_filestats_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static char * ngx_http_filestats(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static char * ngx_http_filestats_get_sizes(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char * ngx_http_filestats_get_times(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
//static char * ngx_http_shm_size(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_int_t ngx_http_filestats_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_filestats_handler_pt(ngx_http_request_t *r);
static ngx_int_t ngx_http_filestats_init(ngx_conf_t *cf);

static ngx_buf_t * ngx_http_filestats_create_response_json(ngx_http_request_t * r);
static ngx_buf_t * ngx_http_filestats_create_response_reset(ngx_http_request_t * r);
static ngx_buf_t * ngx_http_filestats_create_response_html(ngx_http_request_t * r);



static ngx_command_t  ngx_http_filestats_commands[] =
{
    { 
        ngx_string("filestats"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_http_filestats,
        0,
        0,
        NULL 
    },

    {
        ngx_string("filestats_html_table_width"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_filestats_loc_conf_t, html_table_width),
        NULL
    },

    {
        ngx_string("filestats_html_table_height"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_filestats_loc_conf_t, html_table_height),
        NULL
    },

    {
        ngx_string("filestats_refresh_interval"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_filestats_loc_conf_t, refresh_interval),
        NULL
    },

    {
        ngx_string("filestats_file_size"),
        NGX_HTTP_LOC_CONF | NGX_CONF_1MORE,
	ngx_http_filestats_get_sizes,
	NGX_HTTP_LOC_CONF_OFFSET,
	offsetof(ngx_http_filestats_loc_conf_t, size2time),
        NULL
    },

    {
        ngx_string("filestats_time_interval"),
        NGX_HTTP_LOC_CONF | NGX_CONF_1MORE,
	ngx_http_filestats_get_times,
        NGX_HTTP_LOC_CONF_OFFSET,
	0,        
        NULL
    },

    ngx_null_command
};



ngx_http_module_t  ngx_http_filestats_module_ctx =
{
    NULL,                                  /* preconfiguration */
    ngx_http_filestats_init,		   /* postconfiguration */

    NULL,	                           /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_filestats_create_loc_conf,    /* create location configuration */
    ngx_http_filestats_merge_loc_conf,      /* merge location configuration */
};



ngx_module_t  ngx_http_filestats_module =
{
    NGX_MODULE_V1,
    &ngx_http_filestats_module_ctx,        /* module context */
    ngx_http_filestats_commands,           /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

/*****************************************************************************/
/*****************************************************************************/


static void * ngx_http_filestats_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_filestats_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_filestats_loc_conf_t));
    if (conf == NULL)
        return NGX_CONF_ERROR;

    conf->html_table_width = NGX_CONF_UNSET_UINT;
    conf->html_table_height = NGX_CONF_UNSET_UINT;
    conf->refresh_interval = NGX_CONF_UNSET_UINT;

    return conf;
}


/*****************************************************************************/
/*****************************************************************************/


static char* ngx_http_filestats_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_filestats_loc_conf_t *prev = parent;
    ngx_http_filestats_loc_conf_t *conf = child;


    ngx_conf_merge_uint_value(conf->html_table_width, prev->html_table_width, 70);
    ngx_conf_merge_uint_value(conf->html_table_height, prev->html_table_height, 70);
    ngx_conf_merge_uint_value(conf->refresh_interval, prev->refresh_interval, 5000);
    ngx_conf_merge_uint_value(conf->is_reload, prev->is_reload, 1);


    if (conf->html_table_width < 1)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "html table width must be >= 1");
        return NGX_CONF_ERROR;
    }

    if (conf->html_table_height < 1)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "html table height must be >= 1");
        return NGX_CONF_ERROR;
    }

    if (conf->refresh_interval < 1)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "page refresh interval must be >= 1");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


/*****************************************************************************/
/*****************************************************************************/


static ngx_int_t ngx_http_filestats_init_shm(ngx_shm_zone_t * shm_zone, void * data)
{
	if (data)
	{


		shm_zone->data = data;
		return NGX_OK;
	}

	ngx_slab_pool_t *shpool = (ngx_slab_pool_t*)shm_zone->shm.addr;

	void *new_block = ngx_slab_alloc(shpool, filestats_data_size);
	memset(new_block, 0, filestats_data_size);

	shpool->data = new_block;
	shm_zone->data = new_block;

	return NGX_OK;
}

/*****************************************************************************/
/*****************************************************************************/
static char *ngx_http_filestats_get_sizes(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{

	ngx_http_filestats_loc_conf_t  *config = (ngx_http_filestats_loc_conf_t *)conf;
	ngx_str_t *value;
	ngx_int_t  num;
	value = cf->args->elts;
	num = cf->args->nelts;
	ngx_http_filestats_time2size_t *list_element;
	unsigned int i;
    if (ngx_list_init(&config->size2time, cf->pool, 15, sizeof(ngx_http_filestats_time2size_t)) == NGX_ERROR)
		    return "filestats: Error mapping filestats list";

	for (i=1; i<num; i++)
	{
	    list_element = ngx_list_push(&config->size2time);
	    if (list_element == NULL)
		    return "filestats: Error push to size2time list";
	    list_element->strsize = value[i].len;
	    list_element->size = ngx_parse_size(&value[i]);
	}

	filestats_conf = config;
    filestats_conf->is_reload=1;

	return NGX_OK;
};


/*****************************************************************************/
/*****************************************************************************/
static char *ngx_http_filestats_get_times(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_filestats_loc_conf_t  *config = (ngx_http_filestats_loc_conf_t *)conf;
	ngx_str_t *value;
	ngx_int_t  num;
	value = cf->args->elts;
	num = cf->args->nelts;
	ngx_http_filestats_timeouts_t *list_element;
	ngx_list_part_t *part;
	unsigned int i, ii;
	ngx_http_filestats_time2size_t * data;

	part = &config->size2time.part;
	data = part->elts;

	for (i = 0 ;;i++) {
		if (i >= part->nelts) {
			if (part->next == NULL) {
				break;
			}

			part = part->next;
			data = part->elts;
			i = 0;
		}
	    if (ngx_list_init(&data[i].timeouts, cf->pool, 15, sizeof(ngx_http_filestats_timeouts_t)) == NGX_ERROR)
	        return "filestats: Error mapping filestats timeouts list";
	    for (ii=1; ii<num; ii++)
	    {
		    list_element = ngx_list_push(&data[i].timeouts);
		    if (list_element == NULL)
			    return "filestats: Error push to size2time list";
		    list_element->times.msec = ngx_atoi(value[ii].data, value[ii].len);
		    list_element->count = 0;
		    list_element->len = value[ii].len;
	    }
	};
	return NGX_OK;
}

/*****************************************************************************/
/*****************************************************************************/
static char *ngx_http_filestats(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);



    clcf->handler = ngx_http_filestats_handler;

    if (cf->args->nelts == 1)
    {
    	ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "filestats: no shared memory size specified");
    	return NGX_CONF_ERROR;
    }

    ssize_t size = 0;

    ngx_str_t size_arg = ((ngx_str_t*)cf->args->elts)[1];

    if (ngx_strncmp(size_arg.data, "memsize=", 8) == 0)
    {
    	ngx_str_t size_str;

    	size_str.len = size_arg.len - 8;

    	if (size_str.len == 0)
    	{
    		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "filestats: no shared memory size specified");
    		return NGX_CONF_ERROR;
    	}

    	size_str.data = size_arg.data + 8;

    	size = ngx_parse_size(&size_str);
    	if (size == NGX_ERROR)
		{
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "filestats: unable to parse shared memory size");
			return NGX_CONF_ERROR;
		}
    }
    else
    {
    	ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "filestats: no shared memory size specified");
    	return NGX_CONF_ERROR;
    }

    if (size < (int)ngx_pagesize && !filestats_data)
	{
		ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "filestats: shared memory size must be at least %udB", ngx_pagesize);
		size = ngx_pagesize;
	}

	if (filestats_data_size && filestats_data_size != (size_t)size)
		ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "filestats: cannot change shared memory area without restart, ignoring changes");
	else
		filestats_data_size = size;

	ngx_str_t * shm_name = NULL;
	shm_name = ngx_palloc(cf->pool, sizeof(*shm_name));
	shm_name->len = sizeof("filestats_data");
	shm_name->data = (unsigned char*)"filestats_data";

	if (filestats_data_size == 0)
		filestats_data_size = ngx_pagesize;

	filestats_data = ngx_shared_memory_add(cf, shm_name, filestats_data_size + 4 * ngx_pagesize, &ngx_http_filestats_module);

	if (filestats_data == NULL)
		return NGX_CONF_ERROR;

	filestats_data->init = ngx_http_filestats_init_shm;


    return NGX_CONF_OK;
}


/*****************************************************************************/
/*****************************************************************************/


static ngx_int_t ngx_http_filestats_handler(ngx_http_request_t *r)
{
    ngx_int_t rc;
    ngx_buf_t *b = NULL;
    ngx_chain_t out;


    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD)
        return NGX_HTTP_NOT_ALLOWED;

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK)
        return rc;

    ngx_str_set(&r->headers_out.content_type, "text/plain");

    if (r->method == NGX_HTTP_HEAD)
    {
        r->headers_out.status = NGX_HTTP_OK;

        rc = ngx_http_send_header(r);

        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only)
            return rc;
    }

    // Send HTML or simple JSON or reset
    ngx_uint_t send_json = 0;
    ngx_uint_t reset_stat = 0;
    if (r->args.data)
        reset_stat = ngx_strncmp(r->args.data, "reset", 5) ? 0 : 1;

    if (r->args.data)
        send_json = ngx_strncmp(r->args.data, "json", 4) ? 0 : 1;

    if (send_json)
    {
        ngx_str_set(&r->headers_out.content_type, "text/plain");
        b = ngx_http_filestats_create_response_json(r);
    }
    else if (reset_stat)
    {
        ngx_str_set(&r->headers_out.content_type, "text/plain");
        b = ngx_http_filestats_create_response_reset(r);
    }
    else
    {
        ngx_str_set(&r->headers_out.content_type, "text/html");
        b = ngx_http_filestats_create_response_html(r);
    }

    if (b == NULL)
        return NGX_HTTP_INTERNAL_SERVER_ERROR;

    out.buf = b;
    out.next = NULL;

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;

    b->last_buf = 1;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only)
        return rc;

    return ngx_http_output_filter(r, &out);
}


/*****************************************************************************/
/*****************************************************************************/
/*****************************************************************************/
/*****************************************************************************/

static ngx_buf_t * ngx_http_filestats_create_response_reset(ngx_http_request_t * r)
{
        size_t size = 0;
        ngx_buf_t * b = NULL;
	ngx_slab_pool_t          *shpool;

	shpool = (ngx_slab_pool_t *)filestats_data->shm.addr;

	ngx_shmtx_lock(&shpool->mutex);
		ngx_memset(filestats_data->data,0, filestats_data_size);
	ngx_shmtx_unlock(&shpool->mutex);
        size += sizeof("OK\n");

        b = ngx_create_temp_buf(r->pool, size);

        b->last = ngx_sprintf(b->last, "OK\n");

        return b;
}


static ngx_buf_t * ngx_http_filestats_create_response_json(ngx_http_request_t * r)
{
	ngx_list_part_t *part_size2time;
	ngx_list_part_t * part_times;
	ngx_http_filestats_time2size_t * data_size2time;
	ngx_http_filestats_timeouts_t * data_times;
        unsigned i;
        unsigned k;
        size_t size = 0;
        ngx_buf_t * b = NULL;
	char tmpbuf[INTSIZE];

        ngx_http_filestats_loc_conf_t * conf = ngx_http_get_module_loc_conf(r, ngx_http_filestats_module);

        /**
         * Calculate size
         */
        size += sizeof("{\n");
	part_size2time = &conf->size2time.part;
	data_size2time = part_size2time->elts;


        for (i = 0; i < part_size2time->nelts; ++i)
        {
                // size name
                size += sizeof("        \"\":\n");
                size += (data_size2time[i].strsize + 1) * sizeof(u_char);

                // array of timeouts
                size += sizeof("        [\n");

		part_times = &data_size2time[i].timeouts.part;
		data_times = part_times->elts;

                for (k = 0; k < part_times->nelts; ++k)
                {
                        // Times name
                        size += sizeof("                [\"\", ");
			ngx_memset(tmpbuf, 0, INTSIZE);
			sprintf(tmpbuf, "%u", (unsigned int)data_times[k].count);
			size += (strlen(tmpbuf) + 1) * sizeof(u_char);
                        size += sizeof("],\n");
                }

                size += sizeof("                ");
                size += sizeof(ngx_uint_t);

                size += sizeof("        ],\n");
        }

        size += sizeof("}");

        b = ngx_create_temp_buf(r->pool, size);

        b->last = ngx_sprintf(b->last, "{\n");

        /**
         * Fill data
         */
        for (i = 0; i < part_size2time->nelts; ++i)
        {
		if (data_size2time[i].size/1024/1024/1024 >= 1)
		    b->last = ngx_sprintf(b->last, "        \"%dGb\":\n       [\n", data_size2time[i].size/1024/1024/1024);
		else if (data_size2time[i].size/1024/1024 >= 1)
		    b->last = ngx_sprintf(b->last, "        \"%dMb\":\n       [\n", data_size2time[i].size/1024/1024);
		else if (data_size2time[i].size/1024 >= 1)
		    b->last = ngx_sprintf(b->last, "        \"%dKb\":\n       [\n", data_size2time[i].size/1024);
		else
		    b->last = ngx_sprintf(b->last, "        \"%db\":\n       [\n", data_size2time[i].size);

		part_times = &data_size2time[i].timeouts.part;
		data_times = part_times->elts;

                b->last = ngx_sprintf(b->last, "                [");
                for (k = 0; k < part_times->nelts; ++k)
                {
//			if (k==1)
//			    b->last = ngx_sprintf(b->last, "0,0,");	
			if (k < (part_times->nelts-1))
			    b->last = ngx_sprintf(b->last, "%d,", *(ngx_uint_t*)FILESTATS_STAT_ADDRESS(i,k,part_times->nelts));	
			else
			    b->last = ngx_sprintf(b->last, "%d]", data_times[k].count);
                }
			if(i<(part_size2time->nelts-1))
			    b->last = ngx_sprintf(b->last, "\n,%d\n       ],\n", 0);
			else
			    b->last = ngx_sprintf(b->last, "\n,%d\n       ]\n", 0);	

        }

        b->last = ngx_sprintf(b->last, "}\n");

        return b;
}




static ngx_buf_t * ngx_http_filestats_create_response_html(ngx_http_request_t * r)
{
	unsigned int i;
	size_t size = sizeof(FILEHTML) + 3 * sizeof("0000000"); /* table width, height and update timer */
	ngx_buf_t * b = ngx_create_temp_buf(r->pool, size);

	ngx_http_filestats_loc_conf_t * uslc = ngx_http_get_module_loc_conf(r, ngx_http_filestats_module);
	ngx_list_part_t *part_size2time;
	ngx_list_part_t * part_times;
	ngx_http_filestats_time2size_t * data_size2time;
	ngx_http_filestats_timeouts_t * data_times;

	char buf1[8], buf2[8], buf3[100], tmpstring[8];
	ngx_memset(buf1, 0, 8);
	ngx_memset(buf2, 0, 8);
	ngx_memset(buf3, 0, 100);
	ngx_memset(tmpstring, 0, 8);


	part_size2time = &uslc->size2time.part;
	data_size2time = part_size2time->elts;
	part_times = &data_size2time[0].timeouts.part;
	data_times = part_times->elts;
	for (i = 0 ;;i++) {
		if (i >= part_times->nelts) {
			if (part_times->next == NULL) {
				break;
			}

			part_times = part_times->next;
			data_times = part_times->elts;
			i = 0;
		}
		if (i==0)
		    sprintf(tmpstring, "\"< %d msec.\"", (int)data_times[i].times.msec);
		else
		    sprintf(tmpstring, ",\"< %d msec.\"", (int)data_times[i].times.msec);
		    	
		strcat(buf3, tmpstring);
		ngx_memset(tmpstring, 0, 8);
	}

	ngx_sprintf((u_char*)buf1, "%d%s", uslc->html_table_width,
			uslc->html_table_width <= 100 ? "%" : "");
	ngx_sprintf((u_char*)buf2, "%d%s", uslc->html_table_width,
			uslc->html_table_height <= 100 ? "%" : "");

	b->last = ngx_sprintf(b->last, FILEHTML, buf1, buf2, uslc->refresh_interval, buf3);

	return b;
}

static ngx_int_t
ngx_http_filestats_handler_pt(ngx_http_request_t *r)
{
	ngx_list_part_t *part_size2time;
	ngx_list_part_t * part_times;
	ngx_http_filestats_time2size_t * data_size2time;
	ngx_http_filestats_timeouts_t * data_times;
        ngx_uint_t i,k;
	ngx_time_t  *tp;
	ngx_msec_int_t   ms;
	tp = ngx_timeofday();
	ngx_http_filestats_loc_conf_t * uslc = filestats_conf;
	part_size2time = &uslc->size2time.part;
	data_size2time = part_size2time->elts;
/*	ngx_slab_pool_t          *shpool;

	shpool = (ngx_slab_pool_t *)filestats_data->shm.addr;

	ngx_shmtx_lock(&shpool->mutex);
	if (uslc->is_reload)
	{
		uslc->is_reload=0;
		uslc->is_reset=0;
		if (!*(ngx_uint_t*)FILESTATS_STAT_START())
		    *(ngx_uint_t*)FILESTATS_STAT_START() = 1;
	}
	if (*(ngx_uint_t*)FILESTATS_STAT_START())
	{
		ngx_memset(filestats_data->data,0, filestats_data_size);

		*(ngx_uint_t*)FILESTATS_STAT_START() = 0;
	}
	ngx_shmtx_unlock(&shpool->mutex);
*/
	for (i = 0 ;;i++) {

		if (i >= part_size2time->nelts) {
			if (part_size2time->next == NULL) {
				break;
			}

			part_size2time = part_size2time->next;
			data_size2time = part_size2time->elts;
			i = 0;
		}

		if ( r->connection->sent <= data_size2time[i].size )
		{

		    part_times = &data_size2time[i].timeouts.part;
		    data_times = part_times->elts;

		    for (k = 0 ;;k++) {


			if (k >= part_times->nelts) {
			    if (part_times->next == NULL) {
				break;
			    }

			    part_times = part_times->next;
			    data_times = part_times->elts;
			    k = 0;
			}
			ms = (ngx_msec_int_t)((tp->sec - r->start_sec) * 1000 + (tp->msec - r->start_msec));
			ms = ngx_max(ms, 0);

			if ( ms <= (unsigned)data_times[k].times.msec )    
			{
			    if (filestats_data)
				    ngx_atomic_fetch_add((ngx_uint_t*)FILESTATS_STAT_ADDRESS(i,k,part_times->nelts), 1);
			    break;
			};
		    }
		    break;
		};
        }
	return NGX_OK;
}

static ngx_int_t ngx_http_filestats_init(ngx_conf_t *cf)
{
	ngx_http_handler_pt        *h;
	ngx_http_core_main_conf_t  *cmcf;

	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

	h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
	if (h == NULL) {
		return NGX_ERROR;
	}

	*h = ngx_http_filestats_handler_pt;

	return NGX_OK;
}
