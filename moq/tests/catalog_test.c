
#include <stdio.h>
#include <stdlib.h>
#include "moq/moq_media/xqc_moq_catalog.h"
#include "moq/moq_transport/xqc_moq_session.h"

int 
main() 
{
// {
//   "version": 1,
//   "sequence": 0,
//   "streamingFormat": 1,
//   "streamingFormatVersion": "0.2",
//   "namespace": "conference.example.com/conference123/alice",
//   "packaging": "loc",
//   "renderGroup": 1,
//   "tracks": [
//     {
//       "name": "video",
//       "selectionParams":{"codec":"av01.0.08M.10.0.110.09","width":1920,"height":1080,"framerate":30,"bitrate":1500000}
//     },
//     {
//       "name": "audio",
//       "selectionParams":{"codec":"opus","samplerate":48000,"channelConfig":"2","bitrate":32000}
//     }
//    ]
// }
    char *demo_catalog = "{\
     \"version\": 1,\
     \"streamingFormat\": 1,\
     \"streamingFormatVersion\": \"0.2\",\
     \"commonTrackFields\": {\
        \"namespace\": \"sports.example.com/games/08-08-23/12345\",\
        \"packaging\": \"cmaf\",\
        \"renderGroup\":1\
     },\
     \"tracks\": [\
       {\
         \"name\": \"video_1080\",\
         \"selectionParams\":{\"codec\":\"avc1.640028\",\"mimeType\":\"video/mp4\",\
         \"width\":1920,\"height\":1080,\"framerate\":30,\"bitrate\":9914554},\
         \"initData\":\"AAAAGG...BAAAx\"\
       },\
       {\
         \"name\": \"audio_aac\",\
         \"selectionParams\":{\"codec\":\"mp4a.40.5\",\"mimeType\":\"audio/mp4\",\
         \"samplerate\":48000,\"channelConfig\":\"2\",\"bitrate\":67071},\
         \"initData\":\"AAAAGG...EAADE=\"\
       }\
      ]\
   }\"";

    xqc_moq_catalog_t *catalog = (xqc_moq_catalog_t *) malloc(sizeof(xqc_moq_catalog_t));
    xqc_init_list_head(&catalog->track_list_for_sub);
    size_t catalog_len = strlen(demo_catalog);
    catalog->log = NULL;
    xqc_int_t decode_error = xqc_moq_catalog_decode(catalog, demo_catalog, catalog_len);
    fprintf(stderr, "decode error = %d \n", decode_error);
    char buf[800] = {0};
    xqc_int_t length = 0;
    catalog->track_list_for_pub = &catalog->track_list_for_sub;
    xqc_int_t encode_error = xqc_moq_catalog_encode(catalog, buf, 800, &length);
    fprintf(stderr, "encode error = %d \n", encode_error);
    return 0;
}