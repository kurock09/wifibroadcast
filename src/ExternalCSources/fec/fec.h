#ifndef FEC_2_H
#define FEC_2_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct fec_parms *fec_code_t;
typedef unsigned char gf;

/*
 * create a new encoder, returning a descriptor. This contains k,n and
 * the encoding matrix.
 * n is the number of data blocks + fec blocks (matrix height)
 * k is just the data blocks (matrix width)
 */
void fec_init(void);

void fec_encode(unsigned int blockSize,
                const gf **data_blocks,
                unsigned int nrDataBlocks,
                gf **fec_blocks,
                unsigned int nrFecBlocks);

/** Documentation comes from https://github.com/DroneBridge/DroneBridge/blob/55eec5fad91a6faaaf6ac1fdd350d4db21a0435f/video/fec.c
* @param blockSize Size of packets
* @param data_blocks pointer to list of data packets
* @param nr_data_blocks number of data packets
* @param fec_blocks pointer to list of FEC packets
* @param fec_block_nos Indices of FEC packets that shall repair erased data packets in data packet list [array]
* @param erased_blocks Indices of erased data packets in FEC packet data list [array]
* @param nr_fec_blocks Number of FEC blocks used to repair data packets
*/
void fec_decode(unsigned int blockSize,
                gf **data_blocks,
                unsigned int nr_data_blocks,
                gf **fec_blocks,
                const unsigned int fec_block_nos[],
                const unsigned int erased_blocks[],
                unsigned short nr_fec_blocks  /* how many blocks per stripe */);

void fec_print(fec_code_t code, int width);

void fec_license(void);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
#include <vector>
#include <array>
#include "../../HelperSources/StringHelper.hpp"

//Note: By using "blockBuffer" as input the fecEncode / fecDecode function(s) don't need to allocate any new memory.
// The "blockBuffer" can be either at least as big as needed or bigger, implementation doesn't care

/**
 * @param packetSize size of each data packet (fragment) to use for the FEC encoding step. FEC only works on packets the same size
 * @param blockBuffer (big) data buffer. The nth element is to be treated as the nth fragment of the block, either as primary or secondary fragment.
 * During the FEC step, @param nPrimaryFragments fragments are used to calculate nSecondaryFragments FEC blocks.
 * After the FEC step,beginning at idx @param nPrimaryFragments ,@param nSecondaryFragments are stored at the following indices, each of size @param packetSize
 */
template<std::size_t S>
void fecEncode(unsigned int packetSize,std::vector<std::array<uint8_t,S>>& blockBuffer,unsigned int nPrimaryFragments,unsigned int nSecondaryFragments){
    assert(packetSize<=S);
    assert(nPrimaryFragments+nSecondaryFragments<=blockBuffer.size());
    std::vector<uint8_t*> primaryFragments(nPrimaryFragments);
    std::vector<uint8_t*> secondaryFragments(nSecondaryFragments);
    for(int i=0;i<nPrimaryFragments;i++){
        primaryFragments[i]=blockBuffer[i].data();
    }
    for(unsigned int i=0;i<nSecondaryFragments;i++){
        secondaryFragments[i]=blockBuffer[nPrimaryFragments+i].data();
    }
    fec_encode(packetSize, (const unsigned char**)primaryFragments.data(),primaryFragments.size(), (unsigned char**)secondaryFragments.data(), secondaryFragments.size());
}

/**
 * create 2 arrays of data pointers.
 * First one holds pointers to all primary fragments (index 0 = first primary fragment, index 1= second primary fragment, ...
 * And second one holds pointers to all secondary fragments ( index 0 = first secondary fragment, index 1 = second secondary fragment, ...
 */
template<std::size_t S>
std::pair<std::vector<uint8_t*>,std::vector<uint8_t*>> split(std::vector<std::array<uint8_t,S>>& blockBuffer,unsigned int nPrimaryFragments){
    std::vector<uint8_t*> primaryFragmentsP(nPrimaryFragments);
    for(unsigned int i=0;i<nPrimaryFragments;i++){
        primaryFragmentsP[i]=blockBuffer[i].data();
    }
    const int nSecondaryFragmentsPointers=blockBuffer.size()-nPrimaryFragments;
    std::vector<uint8_t*> secondaryFragmentsP(nSecondaryFragmentsPointers);
    for(unsigned int i=0;i<nSecondaryFragmentsPointers;i++){
        secondaryFragmentsP[i]=blockBuffer[nPrimaryFragments+i].data();
    }
    return std::make_pair(primaryFragmentsP,secondaryFragmentsP);
}

/**
 * @param packetSize size of each data packet (fragment) to use for the FEC encoding step. FEC only works on packets the same size
 * @param blockBuffer (big) data buffer. The nth element is to be treated as the nth fragment of the block, either as primary or secondary fragment.
 * During the FEC step, all missing primary Fragments (indices from @param indicesMissingPrimaryFragments) are reconstructed from the FEC packets,
 * using indices from @param indicesAvailableSecondaryFragments
 * Note: both @param indicesMissingPrimaryFragments and @param indicesAvailableSecondaryFragments refer to a position in @param blockBuffer
 */
template<std::size_t S>
void fecDecode(unsigned int packetSize,std::vector<std::array<uint8_t,S>>& blockBuffer,unsigned int nPrimaryFragments,
               const std::vector<unsigned int>& indicesMissingPrimaryFragments,const std::vector<unsigned int>& indicesAvailableSecondaryFragments){
    // first validate input.
    assert(packetSize<=S);
    assert(indicesMissingPrimaryFragments.size()>=indicesAvailableSecondaryFragments.size());
    // I treat calling fecDecode() with more primary fragments than needed for the reconstruction step as an error here
    // (because it would create unneeded latency) though it would work just fine
    assert(indicesMissingPrimaryFragments.size()==indicesAvailableSecondaryFragments.size());
    // unfortunately the fec implementation needs an array of primary fragments
    // and a different array of secondary fragments where obviously the indices of all primary fragments are the same,
    // but the indices for secondary fragments start at 0 and not fec_k
    // ( in this regard, fec_encode() differs from fec_decode() )
    std::vector<uint8_t*> primaryFragmentsP(nPrimaryFragments);
    for(unsigned int i=0;i<nPrimaryFragments;i++){
        primaryFragmentsP[i]=blockBuffer[i].data();
    }
    const int nSecondaryFragmentsPointers=blockBuffer.size()-nPrimaryFragments;
    std::vector<uint8_t*> secondaryFragmentsP(nSecondaryFragmentsPointers);
    for(unsigned int i=0;i<nSecondaryFragmentsPointers;i++){
        secondaryFragmentsP[i]=blockBuffer[nPrimaryFragments+i].data();
    }
    std::vector<unsigned int> indicesAvailableSecondaryFragmentsAdjusted(indicesAvailableSecondaryFragments.size());
    for(int i=0;i<indicesAvailableSecondaryFragments.size();i++){
        indicesAvailableSecondaryFragmentsAdjusted[i]=indicesAvailableSecondaryFragments[i]-nPrimaryFragments;
    }
    std::cout<<"indicesAvailableSecondaryFragmentsAdjusted:"<<StringHelper::vectorAsString(indicesAvailableSecondaryFragmentsAdjusted)<<"\n";

    fec_decode(packetSize,primaryFragmentsP.data(),nPrimaryFragments,secondaryFragmentsP.data(),indicesAvailableSecondaryFragmentsAdjusted.data(),indicesMissingPrimaryFragments.data(),indicesAvailableSecondaryFragmentsAdjusted.size());

    /*std::vector<uint8_t*> primaryFragments(nPrimaryFragments);
    for(unsigned int i=0;i<nPrimaryFragments;i++){
        primaryFragments[i]=blockBuffer[i].data();
    }
    // n of all theoretically possible locations for secondary fragments (could be optimized if the full range is not used)
    const auto nTheoreticalSecondaryFragments=blockBuffer.size()-nPrimaryFragments;
    std::vector<uint8_t*> secondaryFragments(nTheoreticalSecondaryFragments);
    for(unsigned int i=0;i<nTheoreticalSecondaryFragments;i++){
        secondaryFragments[i]=blockBuffer[nPrimaryFragments+i].data();
    }
    fec_decode(packetSize, primaryFragments.data(), nPrimaryFragments, secondaryFragments.data(), indicesAvailableSecondaryFragments.data(), indicesMissingPrimaryFragments.data(), indicesAvailableSecondaryFragments.size());*/
}

template<std::size_t S>
void fecDecode2(unsigned int packetSize,std::vector<std::array<uint8_t,S>>& blockBuffer,unsigned int nPrimaryFragments,
                const std::vector<unsigned int>& indicesReceivedPrimaryFragments,const std::vector<unsigned int>& indicesReceivedSecondaryFragments){
    assert(indicesReceivedPrimaryFragments.size()+indicesReceivedSecondaryFragments.size()==nPrimaryFragments);
    std::vector<unsigned int> indicesMissingPrimaryFragments;
    for(unsigned int i=0;i<nPrimaryFragments;i++){
        auto found=indicesReceivedPrimaryFragments.end() != std::find(indicesReceivedPrimaryFragments.begin(),indicesReceivedPrimaryFragments.end(),i);
        if(!found){
            indicesMissingPrimaryFragments.push_back(i);
        }
    }
    assert(indicesMissingPrimaryFragments.size()==nPrimaryFragments-indicesReceivedPrimaryFragments.size());
    std::cout<<"indicesMissingPrimaryFragments:"<<StringHelper::vectorAsString(indicesMissingPrimaryFragments)<<"\n";

    //
    auto cPointers=split(blockBuffer,nPrimaryFragments);

    std::vector<unsigned int> indicesAvailableSecondaryFragmentsAdjusted(indicesReceivedSecondaryFragments.size());
    for(int i=0;i<indicesReceivedSecondaryFragments.size();i++){
        indicesAvailableSecondaryFragmentsAdjusted[i]=indicesReceivedSecondaryFragments[i]-nPrimaryFragments;
    }
    std::cout<<"indicesAvailableSecondaryFragmentsAdjusted:"<<StringHelper::vectorAsString(indicesAvailableSecondaryFragmentsAdjusted)<<"\n";

    fecDecode(packetSize,blockBuffer,nPrimaryFragments,indicesMissingPrimaryFragments,indicesReceivedSecondaryFragments);

}

#endif

#endif //FEC_2_H

