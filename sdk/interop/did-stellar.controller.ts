import { Controller, Get, Param, Header, HttpStatus, Res } from '@nestjs/common';
import { Response } from 'express';
import { DidStellarService } from './did-stellar.service';

@Controller('1.0/identifiers')
export class DidStellarController {
  constructor(private readonly didStellarService: DidStellarService) {}

  /**
   * Primary invocation entrypoint matching the DIF Universal Resolver Driver standard spec interface.
   * Path signature: GET /1.0/identifiers/:did
   */
  @Get(':did')
  @Header('Content-Type', 'application/did+ld+json')
  async resolveIdentifiers(@Param('did') did: string, @Res() res: Response) {
    const result = await this.didStellarService.resolveDid(did);

    if (result.didResolutionMetadata.error) {
      if (result.didResolutionMetadata.error === 'notFound') {
        return res.status(HttpStatus.NOT_FOUND).json(result);
      }
      return res.status(HttpStatus.BAD_REQUEST).json(result);
    }

    return res.status(HttpStatus.OK).json(result);
  }
}