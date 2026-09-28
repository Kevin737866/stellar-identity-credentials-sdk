import { Module } from '@nestjs/common';
import { CacheModule } from '@nestjs/cache-manager';
import { DidStellarController } from './did-stellar.controller';
import { DidStellarService } from './did-stellar.service';

@Module({
  imports: [
    CacheModule.register({
      ttl: 60 * 60, // 1 hour internal fail-safe fallback TTL
      max: 2000,   // Store up to 2000 unresolved items in active memory sets
    })
  ],
  controllers: [DidStellarController],
  providers: [DidStellarService],
  exports: [DidStellarService]
})
export class DidStellarModule {}