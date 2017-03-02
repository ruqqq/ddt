package main

import (
	"encoding/binary"
	"fmt"
	"github.com/boltdb/bolt"
	"github.com/ruqqq/carbonchain"
	"log"
)

type DatapackWorker struct {
	Db *bolt.DB
}

func (datapackWorker *DatapackWorker) OnReceiveDatapacks(cc *carbonchain.CarbonChain, carbonDb *bolt.DB) {
	datapacks := make([]carbonchain.Datapack, 0)
	datapackIds := make(map[int][]byte)

	// Get all available datapacks
	err := carbonDb.View(func(tx *bolt.Tx) error {
		bDatas := tx.Bucket([]byte("datas"))

		c := bDatas.Cursor()
		for i, datapackByte := c.First(); i != nil; i, datapackByte = c.Next() {
			datapack := *carbonchain.NewDatapackFromBytes(datapackByte)

			datapacks = append(datapacks, datapack)
			index := make([]byte, len(i))
			copy(index, i)
			datapackIds[len(datapacks)-1] = index
		}

		return nil
	})
	if err != nil {
		panic(err)
	}

	// Consume datapacks
	if len(datapacks) > 0 {
		err = datapackWorker.ProcessDatapacks(cc, carbonDb, datapacks, datapackIds)
		if err != nil {
			panic(err)
		}

		//err = carbonDb.Batch(func(tx *bolt.Tx) error {
		//	bDatas := tx.Bucket([]byte("datas"))
		//	err := bDatas.Delete(datapackIds[i])
		//	return err
		//})
		//if err != nil {
		//	panic(err)
		//}

		// Write data to file
		//_, err = f.WriteString(out)
		//if err != nil {
		//	log.Fatal(err)
		//}
	}
}

func (datapackWorker *DatapackWorker) ProcessDatapacks(cc *carbonchain.CarbonChain, carbonDb *bolt.DB, datapacks []carbonchain.Datapack, datapackIds map[int][]byte) error {
	if len(datapacks) > 0 {
		// Open datas file for writing our datapacks data
		//var f *os.File
		//if _, err := os.Stat("ddt.txt"); err != nil {
		//	if os.IsNotExist(err) {
		//		var err error
		//		f, err = os.Create("ddt.txt")
		//		if err != nil {
		//			log.Fatal(err)
		//		}
		//	} else {
		//		f, err = os.OpenFile("ddt.txt", os.O_APPEND, 666)
		//		if err != nil {
		//			log.Fatal(err)
		//		}
		//	}
		//}

		// TODO: Remove this later
		//datapackWorker.Db.Batch(func(tx *bolt.Tx) error {
		//	tx.DeleteBucket([]byte(BUCKET_COMMANDS))
		//	tx.DeleteBucket([]byte(BUCKET_DATAPACKS))
		//	tx.CreateBucket([]byte(BUCKET_COMMANDS))
		//	tx.CreateBucket([]byte(BUCKET_DATAPACKS))
		//
		//	return nil
		//})

		fmt.Printf("Datapacks (%d):\n", len(datapacks))
		for index, datapack := range datapacks {
			//log.Printf("[%s] %x\r\n", datapack.OutputAddr, datapack.Data)
			blockHash, err := cc.GetTransactionBlockHash(datapack.TxIds[0])
			if err != nil {
				log.Fatal(err)
			}
			//log.Printf("-> %x\r\n", blockHash)
			confirmations, err := cc.GetBlockConfirmation(blockHash)
			if err != nil {
				log.Fatal(err)
			}
			//log.Printf("-> %d confirmations\r\n", confirmations)

			// Wait for 6 confirmations
			if confirmations < 6 {
				fmt.Printf("\tNOT CONFIRMED [%s (c: %d)] %+v\r\n", datapack.OutputAddr, confirmations, datapack)
				continue
			}

			var out string
			var command CommandInterface
			switch t := int8(datapack.Data[0]); t {
			case TYPE_REGISTER_ROOT_KEY:
				fallthrough
			case TYPE_DELETE_ROOT_KEY:
				command = NewRootKeyCommandFromBytes(datapack.Data)
			case TYPE_REGISTER_KEY:
				fallthrough
			case TYPE_DELETE_KEY:
				command = NewKeyCommandFromBytes(datapack.Data)
			case TYPE_REGISTER_SIGNATURE:
				fallthrough
			case TYPE_DELETE_SIGNATURE:
				command = NewSignatureCommandFromBytes(datapack.Data)
			default:
				log.Printf("Unrecognized command: [%s (c: %d)] %s\r\n", datapack.OutputAddr, confirmations, datapack.Data)
				// Delete datapack
				err = carbonDb.Batch(func(tx *bolt.Tx) error {
					bDatas := tx.Bucket([]byte("datas"))
					err := bDatas.Delete(datapackIds[index])
					return err
				})
				if err != nil {
					panic(err)
					return err
				}
				continue
			}
			out = fmt.Sprintf("   CONFIRMED  [%s (c: %d)] %+v\r\n", datapack.OutputAddr, confirmations, command)
			fmt.Print("\t" + out)

			validated, err := command.Validate(datapackWorker.Db)
			if err != nil {
				log.Printf("Error verification command: %s. [%s (c: %d)] %+v\r\n", err.Error(), datapack.OutputAddr, confirmations, command)
				// Delete datapack
				err = carbonDb.Batch(func(tx *bolt.Tx) error {
					bDatas := tx.Bucket([]byte("datas"))
					err := bDatas.Delete(datapackIds[index])
					return err
				})
				if err != nil {
					panic(err)
					return err
				}
				continue
			}
			if !validated {
				log.Printf("Command verification failed: [%s (c: %d)] %+v\r\n", datapack.OutputAddr, confirmations, command)
				// Delete datapack
				err = carbonDb.Batch(func(tx *bolt.Tx) error {
					bDatas := tx.Bucket([]byte("datas"))
					err := bDatas.Delete(datapackIds[index])
					return err
				})
				if err != nil {
					panic(err)
					return err
				}
				continue
			}
			err = command.Execute(datapackWorker.Db)
			if err != nil {
				log.Printf("Error executing command: %s\n", err.Error())
				panic(err)
			}

			err = datapackWorker.Db.Batch(func(tx *bolt.Tx) error {
				bCommands := tx.Bucket([]byte(BUCKET_COMMANDS))
				id, _ := bCommands.NextSequence()
				bId := make([]byte, 8)
				binary.BigEndian.PutUint64(bId, uint64(id))
				err := bCommands.Put(bId, command.Bytes())
				if err != nil {
					return err
				}

				bDatapacks := tx.Bucket([]byte(BUCKET_DATAPACKS))
				id, _ = bDatapacks.NextSequence()
				binary.BigEndian.PutUint64(bId, uint64(id))
				err = bDatapacks.Put(bId, datapack.Bytes())
				if err != nil {
					return err
				}

				return nil
			})
			if err != nil {
				// TODO: Should I not panic
				panic(err)
				return err
			}

			err = carbonDb.Batch(func(tx *bolt.Tx) error {
				bDatas := tx.Bucket([]byte("datas"))
				err := bDatas.Delete(datapackIds[index])
				return err
			})
			if err != nil {
				panic(err)
				return err
			}

			log.Printf("Command executed: [%s (c: %d)] %+v\r\n", datapack.OutputAddr, confirmations, command)
		}

		//f.Close()
	}

	return nil
}
