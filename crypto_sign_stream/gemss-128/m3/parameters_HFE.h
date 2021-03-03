#ifndef _PARAMETERS_HFE_H
#define _PARAMETERS_HFE_H


#define K 128U

/* Number of variables of the public-key */
#define HFEnv (HFEn+HFEv)

/* Number of equations of the public-key */
#define HFEm (HFEn-HFEDELTA)

/* GeMSS128 */
#define HFEn 174U
#define HFEv 12U
#define HFEDELTA 12U
#define NB_ITE 4

#endif
