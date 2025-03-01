pragma solidity ^0.8.0; 

contract My{
  uint a  =100;


  function mine() public returns(uint){
    uint result = 0;
    for(uint i =0; i < 100; i++){
      a  += i;
    }

    return result;
   }
}

